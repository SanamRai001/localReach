"use strict";
// Explicitly SIMULATED onboarding. No network, installer, pairing or scanning.
const views=[
 {icon:"⬇",title:"Start with the LocalReach agent",detail:"The agent connects outward securely, so your devices can stay on their local network.",button:"Preview connection"},
 {icon:"↗",title:"Your computer is connected (preview)",detail:"In the real experience, pairing will require authorized approval and a securely enrolled agent identity.",button:"Preview devices"},
 {icon:"▣",title:"Devices stay under your control",detail:"Example capabilities: printer output and attendance events. A future release will discover supported devices and request your approval before sharing access.",button:"Restart preview"}
];
let index=0;
const content=document.getElementById("content");
const next=document.getElementById("next");
const back=document.getElementById("back");
function render(){
 const view=views[index];
 content.replaceChildren();
 const glyph=document.createElement("div");glyph.className="glyph";glyph.textContent=view.icon;
 const h=document.createElement("h2");h.textContent=view.title;
 const p=document.createElement("p");p.textContent=view.detail;
 const notice=document.createElement("div");notice.className="notice";
 const strong=document.createElement("strong");strong.textContent="Preview only — no device access";
 const small=document.createElement("span");small.textContent="This page does not perform real enrollment, networking or discovery.";
 notice.append(strong,small);content.append(glyph,h,p,notice);
 for(let i=0;i<3;i++){const el=document.getElementById("step"+(i+1));el.classList.toggle("on",i<=index);if(i===index){el.setAttribute("aria-current","step")}else{el.removeAttribute("aria-current")}}
 next.textContent=view.button+" →";back.hidden=index===0;
}
next.addEventListener("click",()=>{index=(index+1)%3;render()});
back.addEventListener("click",()=>{index=Math.max(0,index-1);render()});
render();
