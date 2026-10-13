"use strict";
// Real, same-origin local dashboard. No mock state and no secret signing key in JS.
// Action requests require the process-generated CSRF token and strict Origin.
const byId=(id)=>document.getElementById(id);
let csrf="";
let status=null;
let busy=false;
let discovered=[];
function show(message,error=false){
 const box=byId("alert");
 box.textContent=message;
 box.hidden=!message;
 box.classList.toggle("error",error);
}
async function json(response){
 let value;
 try{value=await response.json()}catch(_){throw Error("The local service returned an invalid response.")}
 if(!response.ok)throw Error(value.error||"Local operation failed.");
 return value;
}
async function bootstrap(){
 if(location.origin!=="http://127.0.0.1:18788")throw Error("Open the trusted local address: http://127.0.0.1:18788");
 const response=await fetch("/v1/local/bootstrap",{cache:"no-store",credentials:"omit",redirect:"error"});
 const data=await json(response);
 if(typeof data.csrfToken!=="string"||!data.status)throw Error("Local dashboard could not initialize.");
 csrf=data.csrfToken;
 renderStatus(data.status);
}
async function refresh(){
 const data=await json(await fetch("/v1/local/dashboard",{cache:"no-store",credentials:"omit",redirect:"error"}));
 renderStatus(data);
}
async function action(path,input){
 if(busy||!csrf)return;
 busy=true;
 renderButtons();
 show("");
 try{
  const response=await fetch(path,{
   method:"POST",headers:{"Content-Type":"application/json","X-LocalReach-Token":csrf},
   credentials:"omit",cache:"no-store",redirect:"error",body:JSON.stringify(input)
  });
  const data=await json(response);
  if(data.status)renderStatus(data.status);
  return data;
 }catch(err){
  show(err.message||"Something went wrong.",true);
  return null;
 }finally{
  busy=false;
  renderButtons();
 }
}
function text(id,value){byId(id).textContent=value;}
function renderButtons(){
 const active=!!csrf&&!busy;
 const identityReady=status?.identity==="READY";
 const cloudReady=!!status?.cloudConfigured;
 byId("initialize").disabled=!active||identityReady;
 byId("discover").disabled=!active;
 byId("request").disabled=!active||!cloudReady||!identityReady||!!status?.requestId;
 byId("finish").disabled=!active||!cloudReady||!identityReady||!status?.requestId;
 byId("reconnect").disabled=!active||!cloudReady||!identityReady;
 byId("refresh").disabled=!active;
 byId("invitation").disabled=!active||!cloudReady||!identityReady;
}
function renderStatus(next){
 status=next;
 const identity=next.identity==="READY"?"Identity ready":next.identity==="UNAVAILABLE"?"Key store unavailable":"Not initialized";
 text("identity-label",identity);
 text("identity-hint",next.identity==="READY"?"Stored in your OS secure vault":"Explicit setup required");
 text("fingerprint",next.fingerprint||"No identity has been created");
 text("connection-label",next.connection==="ONLINE"?"Online":"Offline");
 text("connection-hint",next.connection==="ONLINE"?"Authenticated heartbeat stream active":"No live cloud session");
 text("devices-label",next.discovery==="COMPLETE"?String(next.deviceCount)+" observed":next.discovery==="SCANNING"?"Listening…":"Not checked");
 text("devices-hint",next.discovery==="COMPLETE"?"Unverified mDNS announcements":"Passive printer discovery");
 text("pairing-pill",next.pairing.replaceAll("_"," "));
 if(!next.cloudConfigured){
  text("gateway-info","No cloud gateway configured. Identity setup and local discovery work now. Pairing needs an operator-managed HTTPS gateway and organization configured at startup.");
 }else{
  text("gateway-info","Configured for organization "+next.organization+". Enter an invitation from your administrator; approval is required before enrollment.");
 }
 if(next.requestId){
  text("pairing-details","Pairing request "+next.requestId+" is pending. Ask your administrator to review the fingerprint and approve it, then select Finish approved pairing.");
 }else if(next.connection==="ONLINE"){
  text("pairing-details","Identity connected over authenticated HTTPS. No printer or attendance commands are enabled.");
 }else if(next.identity==="READY"){
  text("pairing-details",next.cloudConfigured?"Identity ready. Request an invitation or reconnect if this computer is already enrolled.":"Your identity is ready; cloud pairing is unavailable until a trusted gateway is configured.");
 }else{
  text("pairing-details","Create an OS-protected identity before requesting pairing. No device is shared automatically.");
 }
 if(next.lastError)show(next.lastError,true);
 renderButtons();
}
function renderCandidates(items){
 discovered=items;
 const view=byId("device-results");
 view.replaceChildren();
 if(!Array.isArray(items)||items.length===0){
  const empty=document.createElement("div");empty.className="empty";
  const symbol=document.createElement("span");symbol.textContent="◎";
  const title=document.createElement("strong");title.textContent="No announcements observed";
  const desc=document.createElement("small");desc.textContent="No printer broadcast was seen during the listening window. Try again later; this does not mean no printers exist.";
  empty.append(symbol,title,desc);view.append(empty);return;
 }
 for(const candidate of items){
  const item=document.createElement("div");item.className="device-item";
  const name=document.createElement("strong");name.textContent=(candidate.type||"Device")+" · "+(candidate.name||"Unnamed");
  const note=document.createElement("small");note.textContent="Unverified local announcement · Fingerprint "+(candidate.fingerprint||"unavailable");
  item.append(name,note);view.append(item);
 }
}
byId("refresh").addEventListener("click",async()=>{try{await refresh();show("Local status refreshed.")}catch(e){show(e.message,true)}});
byId("initialize").addEventListener("click",async()=>{
 const data=await action("/v1/local/initialize",{});
 if(data)show("Identity created securely in your OS account. It is not paired or connected yet.");
});
byId("discover").addEventListener("click",async()=>{
 text("discovery-progress","Listening for 8 seconds…");
 const data=await action("/v1/local/discover",{seconds:8});
 text("discovery-progress",data?"Completed · no device was contacted":"Discovery unavailable");
 if(data){
  renderCandidates(data.candidates);
  show(data.candidates?.length?data.candidates.length+" unverified printer announcement(s) observed locally.":"Scan complete. No announcements were observed.");
 }
});
byId("request").addEventListener("click",async()=>{
 const invitation=byId("invitation").value.trim();
 const data=await action("/v1/local/request",{invitation});
 byId("invitation").value="";
 if(data)show("Pairing request submitted. An administrator must explicitly approve it before you can finish.");
});
byId("finish").addEventListener("click",async()=>{
 const data=await action("/v1/local/finish",{});
 if(data)show("Enrollment confirmed. Waiting for an authenticated cloud heartbeat; status will update automatically.");
});
byId("reconnect").addEventListener("click",async()=>{
 const data=await action("/v1/local/reconnect",{});
 if(data)show("Existing identity verified. Starting authenticated cloud connection.");
});
(async()=>{
 try{
  await bootstrap();
  // Status polling is a read-only local GET. Never synthesize ONLINE.
  setInterval(async()=>{if(!busy)try{await refresh()}catch(_){
   text("connection-label","Unavailable");
   text("connection-hint","Local service did not respond");
  }},3500);
 }catch(e){show(e.message,true);text("identity-label","Unavailable");text("connection-label","Unavailable");}
})();
