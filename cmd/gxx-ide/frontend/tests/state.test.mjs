import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import { test } from 'node:test'
import ts from 'typescript'
const root = fileURLToPath(new URL('../src', import.meta.url))
function functions(file, names) {
 const source = fs.readFileSync(path.join(root, file), 'utf8').split('<script setup lang="ts">')[1].split('</script>')[0]
 const ast = ts.createSourceFile('view.ts', source, ts.ScriptTarget.ESNext, true)
 const code = ast.statements.filter(s => ts.isFunctionDeclaration(s) && names.includes(s.name.text)).map(s => s.getText(ast)).join('\n')
 assert.equal(code.match(/async function/g)?.length, names.length)
 return ts.transpileModule(code, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
}
function library(loadYAML) {
 const ref = value => ({ value }); const state = { selectedPath: ref('/library/a.yml'), editingContent: ref('id: a'), editorBusy: ref(false), errorMessage: ref(''), saving: ref(false) }; const saved=[]
 const bindings = { ...state, loadYAML, saveYAML:async (path,content)=>saved.push({path,content}), refresh:async()=>{}, isCanceledError:()=>false }
 const factory=new Function(...Object.keys(bindings),'let openController=null;'+functions('views/LibraryView.vue',['openFile','save'])+';return {openFile,save}')
 return { ...factory(...Object.values(bindings)),state,saved }
}
test('读取失败后保持当前文件和内容绑定', async()=>{
 const view=library(async()=>{throw Error('无法读取')});await view.openFile({path:'/library/b.yml'});await view.save();assert.deepEqual(view.saved,[{path:'/library/a.yml',content:'id: a'}])
})
test('过期的文件响应不能覆盖后续请求或重置忙碌状态',async()=>{
 const pending=[];const view=library(()=>new Promise(resolve=>pending.push(resolve)));const a=view.openFile({path:'/library/b.yml'});const b=view.openFile({path:'/library/c.yml'});pending[0]({path:'/library/b.yml',content:'id: b'});await a;assert.equal(view.state.editorBusy.value,true);assert.equal(view.state.selectedPath.value,'/library/a.yml');pending[1]({path:'/library/c.yml',content:'id: c'});await b;assert.equal(view.state.editingContent.value,'id: c');assert.equal(view.state.editorBusy.value,false)
})
