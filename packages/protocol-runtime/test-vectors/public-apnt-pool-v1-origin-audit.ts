import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {encodeAPNTPoolActionWitnessJsonV1} from "../src/apnt_pool_action_witness_json_v1.js";
import {PUBLIC_REFERENCE_DOMAIN} from "./public-apnt-pool-v1-recipe.js";
import {secp256k1} from "@noble/curves/secp256k1";
import {APNT_POOL_V1_CURVE_ORDER as N,APNT_POOL_V1_DOMAIN_TAGS as TAG} from "../src/apnt_pool_contract_v1.js";
import {APNT_POOL_V1_ACTION_RECORD_OFFSETS as OFF} from "../src/apnt_pool_action_record_v1.js";

// Independent diagnostics; only the three adopted full-field roles below may earn local tickets.
type Audit={start:number;end:number;expected:string;stage:string};
const roles=new WeakMap<object,Map<string,string>>(),audits=new WeakMap<object,Map<string,Audit[]>>();
let caseRoles=new Map<string,string>();
export function beginActionAudit(names:string[]){
 assert.equal(names.length,74);assert.equal(new Set(names).size,74);
 caseRoles=new Map(names.map((name,index)=>[name,"CASE_"+String(index+1).padStart(3,"0")]));
}
export function prepareActionAudit(witness:any):Audit[]{
 const result:Audit[]=[];
 // Source inputs are freshly constructed witness keys/scalars, never record bytes or corpus members.
 witness.inputs.forEach((input:any,slot:number)=>{
  if(typeof input.rerandomizer!=="bigint"||input.rerandomizer<0n||input.rerandomizer>=N)return;
  try{
   const base=secp256k1.Point.fromBytes(input.spendKey33);
   const point=base.add(secp256k1.Point.BASE.multiplyUnsafe(input.rerandomizer));
   if(point.equals(secp256k1.Point.ZERO))return;
   const expected=Buffer.from(point.toBytes(true)).toString("hex");
   const start=(slot===0?OFF.rerandomizedKey0:OFF.rerandomizedKey1)*2;
   result.push({start,end:start+66,expected,stage:slot===0?"SOURCE_PUBLIC_RK0_CURVE":"SOURCE_PUBLIC_RK1_CURVE"});
  }catch{ /* Invalid-key negatives have no independently derived point audit. */ }
 });
 // Independent published tagged-hash/packet recurrence, constructed before output comparison.
 const hash=(tag:string,...parts:Uint8Array[])=>{const h=createHash("sha256").update(new TextEncoder().encode(tag));parts.forEach(part=>h.update(part));return new Uint8Array(h.digest());};
 witness.outputs.forEach((output:any,slot:number)=>{
  try{
   const value=Buffer.alloc(8);value.writeBigUInt64LE(output.valueSats);
   const rcm=hash(TAG.commitmentRandomness,output.recoveryKey32,output.rho32),rt=hash(TAG.recoveryTag,output.recoveryKey32);
   const cm=hash(TAG.commitment,value,output.ownerTag32,output.rho32,rcm,rt);
   const pad=hash(TAG.packetDigest,output.recoveryKey32,output.rho32,cm);
   const packet=new Uint8Array([...value.map((byte,index)=>byte^pad[index]!),...pad.slice(8,16)]);
   for(const[bytes,offset,stage]of [[cm,slot===0?OFF.commitment0:OFF.commitment1,slot===0?"SOURCE_PUBLIC_CM0_HASH":"SOURCE_PUBLIC_CM1_HASH"],[packet,slot===0?OFF.packet0:OFF.packet1,slot===0?"SOURCE_PUBLIC_PACKET0_HASH":"SOURCE_PUBLIC_PACKET1_HASH"]] as const){
    const start=offset*2;result.push({start,end:start+bytes.length*2,expected:Buffer.from(bytes).toString("hex"),stage});
   }
  }catch{ /* Out-of-range negative witnesses have no canonical public output construction audit. */ }
 });return result;
}
export function bindActionAudit(root:any,name:string,proof:Audit[],inputBinding?:string){
 const id=caseRoles.get(name);assert(id);
 const map=new Map<string,string>(),put=(path:(string|number)[],role:string)=>map.set(JSON.stringify(path),id+"_"+role);
 put(["record"],"RECORD");
 for(const kind of ["inputs","outputs"]){
  for(let slot=0;slot<2;slot++){
   const fields=kind==="inputs"?["valueSats","spendKey33","nullifierKey32","rho32","commitmentRandomness32","recoveryTag32","rerandomizer"]:["valueSats","ownerTag32","rho32","recoveryKey32"];
   fields.forEach((field,index)=>put(["witness",kind,slot,field],(kind==="inputs"?"INPUT_":"OUTPUT_")+slot+"_FIELD_"+index));
   if(kind==="inputs")for(let height=0;height<32;height++)put(["witness",kind,slot,"membership","siblings",height],"INPUT_"+slot+"_PUBLIC_PATH");
  }
 }
 roles.set(root,map);audits.set(root,new Map([[JSON.stringify(["record"]),proof]]));
 if(inputBinding!==undefined)sourceInputs.set(root,inputBinding);
}
export function actionAuditsFor(root:any){
 const result:{path:(string|number)[];role:string;proof:Audit[]}[]=[];
 function visit(value:any,path:(string|number)[]){
  if(!value||typeof value!=="object")return;
  for(const[p,role]of roles.get(value)||[])result.push({path:path.concat(JSON.parse(p)),role,proof:audits.get(value)?.get(p)||[]});
  if(Array.isArray(value))value.forEach((item,index)=>visit(item,path.concat(index)));
  else for(const[k,item]of Object.entries(value))visit(item,path.concat(k));
 }visit(root,[]);return result;
}

/** Local eligibility is confined to the three adopted constructor/field pairs. */
const eligibleFullFields=new Map([
 ["CASE_007_RECORD",["SOURCE_PUBLIC_PACKET1_HASH",OFF.packet1*2,16*2]],
 ["CASE_028_RECORD",["SOURCE_PUBLIC_RK1_CURVE",OFF.rerandomizedKey1*2,33*2]],
 ["CASE_040_RECORD",["SOURCE_PUBLIC_RK1_CURVE",OFF.rerandomizedKey1*2,33*2]],
] as const);
const sourceInputs=new WeakMap<object,string>();
export function preparePublicInputBinding(witness:any){
 return JSON.stringify(encodeAPNTPoolActionWitnessJsonV1(witness));
}
export function fullPublicFieldOrigins(root:any,target:any=root){
 const need=(ok:unknown,code:string)=>{if(!ok)throw Object.assign(new Error(),{code});};
 need(root.publicReferenceDomain===PUBLIC_REFERENCE_DOMAIN&&target.publicReferenceDomain===PUBLIC_REFERENCE_DOMAIN,"FULL_FIELD_PUBLIC_RECIPE");
 const result:{path:(string|number)[];role:string;stage:string;spans:{start:number;end:number;expected:string;site:string}[]}[]=[];
 function visit(value:any,path:(string|number)[]){
  if(!value||typeof value!=="object")return;
  const role=roles.get(value)?.get(JSON.stringify(["record"]));
  const eligible=role&&eligibleFullFields.get(role as any);
  if(eligible){
   const actual=path.reduce((item,key)=>item?.[key],target),binding=sourceInputs.get(value);
   need(actual&&actual.name===value.name&&caseRoles.get(value.name)+"_RECORD"===role,"FULL_FIELD_CONSTRUCTOR_ROLE");
   need(typeof binding==="string"&&JSON.stringify(value.witness)===binding&&JSON.stringify(actual.witness)===binding,"FULL_FIELD_PUBLIC_INPUT_DRIFT");
   const[stage,start,length]=eligible;
   const proof=(audits.get(value)?.get(JSON.stringify(["record"]))||[]).filter(item=>item.stage===stage&&item.start===start&&item.end===start+length);
   need(proof.length===1&&proof[0]!.expected.length===length,"FULL_FIELD_SOURCE_PROOF");
   const expected=proof[0]!.expected;
   need(typeof actual.record==="string"&&actual.record.length===628&&/^[0-9a-f]+$/.test(actual.record)&&actual.record.slice(start,start+length)===expected,"FULL_FIELD_BYTES_OR_ENCODING");
   result.push({path:path.concat("record"),role:role!,stage,spans:[{start,end:start+length,expected,site:"full-field:"+role+":"+stage}]});
  }
  if(Array.isArray(value))value.forEach((item,index)=>visit(item,path.concat(index)));
  else for(const[key,item]of Object.entries(value))visit(item,path.concat(key));
 }
 visit(root,[]);
 need(result.length===3&&new Set(result.map(item=>item.role)).size===3,"FULL_FIELD_CONSTRUCTOR_SET");
 return result;
}
