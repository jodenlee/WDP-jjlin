import re
import glob
import os

templates_dir = r'c:/Users/neowe/OneDrive/Documents/GitHub/WDP-jjlin/templates'
templates = glob.glob(os.path.join(templates_dir, '**/*.html'), recursive=True)

for filepath in templates:
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Remove data-i18n and data-i18n-placeholder attributes
    cleaned = re.sub(r' data-i18n(?:-placeholder)?="[^"]*"', '', content)
    
    if cleaned != content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(cleaned)
        print(f'Cleaned: {filepath}')

print(f'Done! Processed {len(templates)} templates')
