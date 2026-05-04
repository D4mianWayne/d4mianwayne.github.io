import os
import yaml

posts_dir = r"d:\Projects\d4mianwayne.github.io\posts"
for root, dirs, files in os.walk(posts_dir):
    for file in files:
        if file.endswith(".md"):
            filepath = os.path.join(root, file)
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            if content.startswith('---'):
                end = content.find('---', 3)
                if end != -1:
                    fm = content[3:end]
                    try:
                        parsed = yaml.safe_load(fm)
                        if isinstance(parsed.get('date'), list):
                            print(f"Array date in {filepath}")
                        if 'date' not in parsed:
                            print(f"No date in {filepath}")
                    except Exception as e:
                        print(f"YAML error in {filepath}: {e}")
