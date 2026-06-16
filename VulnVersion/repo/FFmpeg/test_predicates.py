import re

vuln_text = """        if (marker == JPEG_MARKER_SOS) {
            length = AV_RB16(frag->data + start);

            data_ref = NULL;
            data     = av_malloc(end - start +
                                 AV_INPUT_BUFFER_PADDING_SIZE);
"""

fix_text = """        if (marker == JPEG_MARKER_SOS) {
            length = AV_RB16(frag->data + start);

            if (length > end - start)
                return AVERROR_INVALIDDATA;

            data_ref = NULL;
            data     = av_malloc(end - start +
                                 AV_INPUT_BUFFER_PADDING_SIZE);
"""

def test_vuln(text):
    return re.search(r'if\s*\(\s*marker\s*==\s*JPEG_MARKER_SOS\s*\)\s*\{\s*length\s*=\s*AV_RB16\([^)]+\);\s*data_ref\s*=\s*NULL;\s*data\s*=\s*av_malloc', text) is not None

def test_fix(text):
    return re.search(r'if\s*\(\s*marker\s*==\s*JPEG_MARKER_SOS\s*\)\s*\{\s*length\s*=\s*AV_RB16\([^)]+\);\s*if\s*\(\s*length\s*>\s*end\s*-\s*start\s*\)\s*return\s*AVERROR_INVALIDDATA;\s*data_ref\s*=\s*NULL;', text) is not None

print("Vuln text - Vuln Predicate:", test_vuln(vuln_text))
print("Vuln text - Fix Predicate:", test_fix(vuln_text))
print("Fix text - Vuln Predicate:", test_vuln(fix_text))
print("Fix text - Fix Predicate:", test_fix(fix_text))
