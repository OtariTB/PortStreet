with open('tools/lift_catalog.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('if m in ("ret", "retf"):\n        return (0, 0)',
                    'if m in ("ret", "retf", "repz ret", "rep ret"):\n        return (0, 0)')
text = text.replace('if m in ("ret", "retf"):\r\n        return (0, 0)',
                    'if m in ("ret", "retf", "repz ret", "rep ret"):\r\n        return (0, 0)')

text = text.replace('if m in ("ret", "retf"):\n                    imm = ins.operands',
                    'if m in ("ret", "retf", "repz ret", "rep ret"):\n                    imm = ins.operands')
text = text.replace('if m in ("ret", "retf"):\r\n                    imm = ins.operands',
                    'if m in ("ret", "retf", "repz ret", "rep ret"):\r\n                    imm = ins.operands')

with open('tools/lift_catalog.py', 'w', encoding='utf-8') as f:
    f.write(text)
print("Updated lift_catalog.py")
