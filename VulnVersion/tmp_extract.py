import json, sys  
with open('DataSet/Dataset.json', 'rb') as f:  
    data = json.load(f)  
entry = data.get('CVE-2022-0433', {})  
out = json.dumps(entry, indent=2, ensure_ascii=False)[:5000]  
sys.stdout.write(out)  
sys.stdout.flush() 
