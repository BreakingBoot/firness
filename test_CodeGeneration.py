from CodeGeneration import CodeGeneration as gen
import json



f = open('compressed_service_results.json')
data = json.load(f)
f.close()


generate = gen(data, 'TestCodeGeneration')
generate.generate_function_harness()