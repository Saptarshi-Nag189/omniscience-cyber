# Fix shell.py indentation
with open('C:/temp/omniscience-cyber/rag/shell.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    stripped = line.lstrip()
    # Fix function definitions - should be at 4 spaces (class level)
    if line.strip().startswith('def ') and 'self' in line:
        if not line.startswith('    def '):
            # Remove leading whitespace and add 4 spaces
            new_lines.append('    ' + line.lstrip())
        else:
            new_lines.append(line)
        continue
    # Fix method bodies - should be at 8 spaces (4 for class + 4 for method)
    stripped = line.lstrip()
    if stripped and not line.startswith('    ') and not line.startswith('        ') and not line.startswith('\t') and not stripped.startswith('def ') and not stripped.startswith('class ') and not stripped.startswith('"""') and not stripped.startswith('@'):
        new_lines.append('        ' + stripped)
    else:
        new_lines.append(line)

with open('C:/temp/omniscience-cyber/rag/shell.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print('Fixed indentation')