import asyncio,json
from koda_mcp.contracts import ChangedFilesRequest,ChangedFile
from koda_mcp.scan_service import scan_changed_files
async def main():
 cases={
 'cross_function_taint':('cross.py','import subprocess\nx = "echo fixed"\ndef first(request):\n    x = request.args["cmd"]\ndef second():\n    subprocess.run(x, shell=True)\n'),
 'k8s_plain':('k8s/pod.yaml','apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: app\n      securityContext:\n        privileged: true\n'),
 'k8s_comment':('k8s/pod.yaml','apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: app\n      securityContext:\n        privileged: true # explanation\n'),
 'six_same_rule':('a.py','\n'.join('eval(input())' for _ in range(6))),
 'unsupported_extension':('a.svelte','<script>eval(request.query.code)</script>'),
 'normal_extension':('a.js','eval(request.query.code)'),
 'library_named':('jquery-1.2.3.js','eval(request.query.code)'),
 'long_line_hides_other_line':('a.js','//'+('x'*2001)+'\neval(request.query.code)'),
 }
 for label,(name,content) in cases.items():
  r=await scan_changed_files(ChangedFilesRequest(files=[ChangedFile(path=name,content=content)],standard='all'))
  print(json.dumps({'case':label,'status':r.execution_status,'gaps':r.coverage_gaps,'unevaluated_files':[item.model_dump() for item in r.unevaluated_files],'truncated':r.findings_truncated,'findings':[(f.rule_id,f.line,f.verification_status) for f in r.findings]}))
if __name__=='__main__':asyncio.run(main())
