const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/things-BBBBBBBB.js","assets/style-Bbbbbbbb.css","assets/files-CCCCCCCC.js"])))=>i.map(i=>d[i]);
const cookieName="simlessly_token";
async function send(e,t,n={},r={}){n.url=e;n.method=t;const{data:s}=await http(n);if(s&&s.success===!1)throw s.msg;return s}
http.interceptors.request.use(function(e){e.headers.set("Simlessly-Token",tok());e.headers.set("Simlessly-Timestamp",Date.now().toString());return e});
http.interceptors.response.use(function(e){const{data:t}=e;return["20001","20002"].includes(t.code.toString())?(logout(),Promise.reject(t.msg)):e});
function getq(e,t,n={},r){return n.params=t||n.params,send(e,"get",n,r)}
function upload(e,t,n={},r){const s=new FormData;for(const[o,i]of Object.entries(t)){i!=null&&s.append(o,i)}return n.data=s||n.data,send(e,"post",n,r)}
function postj(e,t,n={},r){return n.data=t||n.data,send(e,"post",n,r)}
function doLogin(e){return postj("/api/v1/account/login",e)}
function doLogout(){return getq("/api/v1/account/logout",{})}
function ownerInfo(e){return getq("/api/v1/owner/info",e)}
const theme={actions:{load(){return fetch("https://portal.example.test/api/v1/site/info").then(e=>e.json())}}};
const router=[{path:"/things",component:()=>__vite__preload(()=>import("./things-BBBBBBBB.js"),__vite__mapDeps([0,1]))}];
function unrelated(e,t){e.data=t;return e}
export{postj as p,getq as g,upload as u,doLogin as d};
