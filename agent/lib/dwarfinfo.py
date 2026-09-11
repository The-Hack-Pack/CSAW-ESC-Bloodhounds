#!/usr/bin/env python3
"""
Exact stack layout from DWARF, via pyelftools.

cle parses debug info but drops what matters most here: ArrayType.byte_size is
None and the element count lives in a DW_TAG_subrange_type child DIE that cle
does not expose. Without the count, `uint8_t name[32]` has no size, symex falls
back to the distance from the buffer to the frame's CFA (64 bytes for
parse_config), and every overflow of 33..61 bytes -- which is the actual
planted bug -- is reported as no overflow.

So the array extent is read from the DIE tree directly. DW_AT_frame_base is
DW_OP_call_frame_cfa on every GCC/Clang build we care about, which makes the
DW_OP_fbreg offset in a local's DW_AT_location a CFA offset, matching what
symex computes from the entry stack pointer.
"""
import json
import os

_CACHE = {}

_TRANSPARENT = ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type",
                "DW_TAG_restrict_type", "DW_TAG_atomic_type")


def _deref(die, attr="DW_AT_type"):
    a = die.attributes.get(attr)
    if a is None:
        return None
    try:
        return die.cu.get_DIE_from_refaddr(a.value + die.cu.cu_offset)
    except Exception:
        return None


def _type_size(die, ptr_size, depth=0):
    if die is None or depth > 12:
        return None
    bs = die.attributes.get("DW_AT_byte_size")
    if bs is not None:
        return bs.value
    if die.tag == "DW_TAG_pointer_type":
        return ptr_size
    if die.tag == "DW_TAG_array_type":
        el = _type_size(_deref(die), ptr_size, depth + 1)
        if el is None:
            return None
        count = None
        for ch in die.iter_children():
            if ch.tag != "DW_TAG_subrange_type":
                continue
            if "DW_AT_count" in ch.attributes:
                count = ch.attributes["DW_AT_count"].value
            elif "DW_AT_upper_bound" in ch.attributes:
                ub = ch.attributes["DW_AT_upper_bound"].value
                if isinstance(ub, int):
                    count = ub + 1
        return el * count if isinstance(count, int) else None
    if die.tag in _TRANSPARENT:
        return _type_size(_deref(die), ptr_size, depth + 1)
    return None


def _type_name(die, depth=0):
    if die is None or depth > 12:
        return "?"
    n = die.attributes.get("DW_AT_name")
    if n is not None and die.tag != "DW_TAG_array_type":
        return n.value.decode(errors="replace")
    if die.tag == "DW_TAG_array_type":
        return "%s[]" % _type_name(_deref(die), depth + 1)
    if die.tag == "DW_TAG_pointer_type":
        return "%s*" % _type_name(_deref(die), depth + 1)
    if die.tag in _TRANSPARENT:
        return _type_name(_deref(die), depth + 1)
    return die.tag.replace("DW_TAG_", "")


def _fbreg_offset(die):
    """CFA offset from a DW_AT_location of the form DW_OP_fbreg <sleb128>."""
    loc = die.attributes.get("DW_AT_location")
    if loc is None or not isinstance(loc.value, (list, bytes, bytearray)):
        return None
    b = bytes(loc.value)
    if not b or b[0] != 0x91:          # DW_OP_fbreg
        return None
    val, shift, i = 0, 0, 1
    while i < len(b):
        byte = b[i]
        val |= (byte & 0x7F) << shift
        shift += 7
        i += 1
        if not byte & 0x80:
            if byte & 0x40:
                val -= (1 << shift)
            break
    return val


def stack_layout(binary):
    """{function_name: {"cfa_uses_frame_base": bool, "locals": [...]}}"""
    binary = os.path.abspath(binary)
    if binary in _CACHE:
        return _CACHE[binary]
    out = {}
    try:
        from elftools.elf.elffile import ELFFile
        with open(binary, "rb") as fh:
            elf = ELFFile(fh)
            if not elf.has_dwarf_info():
                _CACHE[binary] = out
                return out
            ptr = elf.elfclass // 8
            dw = elf.get_dwarf_info()
            for cu in dw.iter_CUs():
                for die in cu.iter_DIEs():
                    if die.tag != "DW_TAG_subprogram":
                        continue
                    nm = die.attributes.get("DW_AT_name")
                    if nm is None:
                        continue
                    fname = nm.value.decode(errors="replace")
                    fb = die.attributes.get("DW_AT_frame_base")
                    fb_is_cfa = bool(fb is not None and bytes(fb.value)[:1] == b"\x9c")
                    locs = []
                    stack = list(die.iter_children())
                    while stack:
                        ch = stack.pop()
                        if ch.tag == "DW_TAG_lexical_block":
                            stack.extend(ch.iter_children())
                            continue
                        if ch.tag not in ("DW_TAG_variable", "DW_TAG_formal_parameter"):
                            continue
                        cn = ch.attributes.get("DW_AT_name")
                        if cn is None:
                            continue
                        off = _fbreg_offset(ch)
                        if off is None:
                            continue
                        td = _deref(ch)
                        locs.append({
                            "name": cn.value.decode(errors="replace"),
                            "cfa_offset": off,
                            "size": _type_size(td, ptr),
                            "type": _type_name(td),
                            "is_param": ch.tag == "DW_TAG_formal_parameter",
                        })
                    if locs:
                        out[fname] = {"cfa_uses_frame_base": fb_is_cfa,
                                      "locals": sorted(locs, key=lambda x: x["cfa_offset"])}
    except Exception:
        pass
    _CACHE[binary] = out
    return out


def capacity_at(binary, func, cfa_offset):
    """Bytes available at a CFA offset, plus the local it belongs to."""
    fn = stack_layout(binary).get(func)
    if not fn:
        return None, None
    exact = [l for l in fn["locals"] if l["cfa_offset"] == cfa_offset and l["size"]]
    if exact:
        return exact[0]["size"], exact[0]
    for l in fn["locals"]:
        if l["size"] and l["cfa_offset"] <= cfa_offset < l["cfa_offset"] + l["size"]:
            return l["cfa_offset"] + l["size"] - cfa_offset, l
    return None, None


if __name__ == "__main__":
    import sys
    b = sys.argv[1]
    lay = stack_layout(b)
    want = sys.argv[2:] or sorted(lay)
    for f in want:
        if f not in lay:
            continue
        print("%s (frame_base=CFA: %s)" % (f, lay[f]["cfa_uses_frame_base"]))
        for l in lay[f]["locals"]:
            print("   %-10s cfa%+-5d size=%-5s %-12s %s"
                  % (l["name"], l["cfa_offset"], l["size"], l["type"],
                     "param" if l["is_param"] else ""))
