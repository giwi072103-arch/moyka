let sessionToken=null;
export const authHeaders=()=>sessionToken?{Authorization:`Bearer ${sessionToken}`} : {};
export async function api(path,options={}) {
 const {body,...rest}=options;
 const response=await fetch(`/api${path}`,{...rest,credentials:'same-origin',headers:{...authHeaders(),...(body?{'Content-Type':'application/json'}:{}),...rest.headers},body:body?JSON.stringify(body):undefined});
 const data=await response.json().catch(()=>({error:'Сервер недоступен'}));
 if(!response.ok)throw new Error(data.error||'Не удалось выполнить запрос');if(path==='/auth/telegram')sessionToken=data.token;if(path==='/auth/logout')sessionToken=null;return data;
}
export const money=value=>new Intl.NumberFormat('ru-RU').format(Number(value));
export const statusLabels={queued:'В очереди',accepted:'Заказ принят',washing:'Идёт мойка',ready:'Можно забирать',completed:'Завершён',cancelled:'Отменён'};
export const date=value=>new Intl.DateTimeFormat('ru-RU',{day:'numeric',month:'short',hour:'2-digit',minute:'2-digit',timeZone:'Asia/Tashkent'}).format(new Date(value));
