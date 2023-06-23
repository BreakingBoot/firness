from CodeGeneration import CodeGeneration as gen
import json



f = open('sample_input.json')
data = json.load(f)
f.close()

f = open('well_formed_types.json')
well_formed = json.load(f)
f.close()

generate = gen(data, well_formed, 'TestCodeGeneration')
generate.generate_function_harness()