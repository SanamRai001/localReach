"use strict";
// LocalReach preview shell. Only status GET is live; no browser pairing,
// device discovery, key handling or cloud enrollment occurs in this page.
const views=[
 {icon:"⬇",title:"Start with the LocalReach agent",detail:"Install the signed agent when a release is available. A real installation is not performed by this preview.",button:"Check connection"},
 {icon:"↗",title:"Connect securely — approval required",detail:"The agent must prove its identity and receive administrator approval before pairing. Checking status does not connect anything.",button:"View device permissions"},
 {icon:"▣",title:"Choose devices after pairing",detail:"Printer or attendance access will need separate device discovery and explicit permissions. No device has been shared.",button:"Restart preview"}
];
let index=0;
let revision=0;
const content=document.getElementById("content");
const next=document.getElementById("next");
const back=document.getElementById("back");
function element(tag,text,className){
 const out=document.createElement(tag);
 if(className)out.className=className;
 out.textContent=text;
 return out;
}
function render(){
 revision++;
 const currentRevision=revision;
 const view=views[index];
 const glyph=element("div",view.icon,"glyph");
 const h=element("h2",view.title);
 const p=element("p",view.detail);
 const notice=element("div","","notice");
 notice.append(
  element("strong","Preview only — no device access"),
  element("span","The local status endpoint is read-only. No pairing or discovery action is available here.")
 );
 content.replaceChildren(glyph,h,p,notice);
 for(let i=0;i<3;i++){
  const step=document.getElementById("step"+(i+1));
  step.classList.toggle("on",i<=index);
  if(i===index)step.setAttribute("aria-current","step");
  else step.removeAttribute("aria-current");
 }
 next.textContent=view.button+" →";
 back.hidden=index===0;
 if(index===1)void readLocalStatus(currentRevision);
}
async function readLocalStatus(expectedRevision){
 const notice=element("div","","notice");
 const heading=element("strong","Read-only local status");
 const value=element("span","Checking local status…");
 notice.append(heading,value);
 content.append(notice);
 if(location.protocol!=="http:"||location.host!=="127.0.0.1:18788"){
  value.textContent="Unavailable: open the trusted 127.0.0.1 setup preview.";
  return;
 }
 try{
  const response=await fetch("/v1/local/status",{method:"GET",credentials:"omit",cache:"no-store",redirect:"error"});
  if(!response.ok)throw Error("status unavailable");
  const s=await response.json();
  if(!["RUNNING","STOPPED"].includes(s.agent)||
     !["NOT_PAIRED","PENDING_APPROVAL","PAIRED","REVOKED","EXPIRED"].includes(s.pairing)||
     !["ONLINE","OFFLINE"].includes(s.connection))throw Error("unrecognized status");
  if(expectedRevision!==revision||index!==1)return;
  value.textContent="Agent: "+s.agent+" · Pairing: "+s.pairing+" · Cloud: "+s.connection+".";
  if(s.pairing!=="PAIRED"||s.connection!=="ONLINE"){
   value.textContent+=" Pairing or verified cloud connectivity is not complete.";
  }
 }catch(_){
  if(expectedRevision===revision&&index===1)
   value.textContent="Unavailable: no trusted local agent status has been provided.";
 }
}
next.addEventListener("click",()=>{index=(index+1)%3;render()});
back.addEventListener("click",()=>{index=Math.max(0,index-1);render()});
render();
