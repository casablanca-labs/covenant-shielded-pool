import {createHash} from "node:crypto";
import {describe,expect,it} from "vitest";
import {apntPoolEmptyRootsV1,deriveAPNTPoolMembershipPathV1,apntPoolMembershipRootV1} from "../src/apnt_pool_tree_v1.js";
const h=(a:Uint8Array,b:Uint8Array)=>new Uint8Array(createHash("sha256").update("APNT-POOL-v1:node").update(a).update(b).digest());
const leaf=(n:number)=>new Uint8Array(createHash("sha256").update(`public-rehearsal-tree:${n}`).digest());
describe("rehearsal tree membership",()=>{
 it("matches an independent empty-root recurrence and returns detached roots",()=>{
  const roots=apntPoolEmptyRootsV1();expect(roots).toHaveLength(33);let z=new Uint8Array(32);expect(roots[0]).toEqual(z);
  for(let i=1;i<=32;i++){z=h(z,z);expect(roots[i]).toEqual(z);}
  roots[0]![0]=1;expect(apntPoolEmptyRootsV1()[0]).toEqual(new Uint8Array(32));
 });
 it("three distinct leaf paths reach the independently calculated root",()=>{
  const ls=[leaf(0),leaf(1),leaf(2)],zs=apntPoolEmptyRootsV1();let root=h(h(ls[0]!,ls[1]!),h(ls[2]!,zs[0]!));
  for(let i=2;i<32;i++)root=h(root,zs[i]!);
  for(let i=0;i<ls.length;i++)expect(apntPoolMembershipRootV1(ls[i],deriveAPNTPoolMembershipPathV1(ls,i))).toEqual(root);
 });
 it("a changed sibling changes the reached root and a short path is refused",()=>{
  const ls=[leaf(0),leaf(1)],p=deriveAPNTPoolMembershipPathV1(ls,0),root=apntPoolMembershipRootV1(ls[0],p);
  const changed={position:p.position,siblings32:p.siblings32.map(x=>new Uint8Array(x))};changed.siblings32[0]![0]=changed.siblings32[0]![0]!^1;
  expect(apntPoolMembershipRootV1(ls[0],changed)).not.toEqual(root);
  expect(()=>apntPoolMembershipRootV1(ls[0],{...p,siblings32:p.siblings32.slice(1)})).toThrowError("pool-membership");
 });
 it("refuses a position outside the present leaves and a short leaf",()=>{
  for(const pos of [-1,1,0.5])expect(()=>deriveAPNTPoolMembershipPathV1([leaf(0)],pos)).toThrowError("pool-membership");
  expect(()=>deriveAPNTPoolMembershipPathV1([new Uint8Array(31)],0)).toThrowError("pool-membership");
 });
});
