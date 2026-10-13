import{p as t,g as n,u as a}from"./index-AAAAAAAA.js";
import{x as helper}from"./files-CCCCCCCC.js";
function list(e){return t("/api/v1/things/list",e)}
function detail(e){return n("/api/v1/things/detail",e)}
function add(e){return a("/api/v1/things/import",e)}
function remove(e){return t("/api/v1/things/delete",e)}
function download(){window.open("https://portal.example.test/api/v1/things/key")}
function sheet(e){return axiosLike({url:"/api/v1/things/export",method:"post",data:e,responseType:"blob"})}
function open2(e){return t(`/api/v1/things/${e.kind}/render/${e.id}`,e)}
export{list as l,detail as d,add as a,remove as r};
