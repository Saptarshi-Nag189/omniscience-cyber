# Fix shell.py indentation and issues
with open('C:/temp/omniscience-cyber/rag/shell.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix the indentation issue - the do_run and do_plan methods need proper indentation
# The issue is that function bodies need 8 spaces (4 for class + 4 for function)
lines = content.split('\n')
new_lines = []
in_do_run = False
in_do_plan = False

for line in lines:
    # Fix do_run function
    if line.strip().startswith('def do_run'):
        in_do_run = True
        new_lines.append(line)
        continue
    if in_do_run:
        if line.strip() and not line.startswith('    ') and not line.strip().startswith('"""') and not line.strip().startswith('def ') and not line.strip().startswith('class '):
            # This is a body line that needs indentation
            new_lines.append('    ' + line.lstrip())
        else:
            in_do_run = False
            new_lines.append(line)
        continue
    
    # Fix do_plan
    if line.strip().startswith('def do_plan'):
        in_do_plan = True
        new_lines.append(line)
        continue
    if in_do_plan:
        if line.strip() and not line.startswith('    ') and not line.strip().startswith('"""') and not line.strip().startswith('def ') and not line.strip().startswith('class '):
            new_lines.append('    ' + line.lstrip())
        else:
            in_do_plan = False
            new_lines.append(line)
        continue
    
    new_lines.append(line)

with open('C:/temp/omniscience-cyber/rag/shell.py', 'w', encoding='utf-8') as f:
    f.write('\n'.join(new_lines))

print('Fixed shell.py')