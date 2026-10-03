/* Personal configuration downloads are explicit POSTs, never cached. */
(function(){
  'use strict';
  var catalog=window.FodderCatalog, grid=document.getElementById('server-grid');
  var busy=false, current=null, loading=false, staleCatalog=false, activeServer=null;
  var telegram=window.Telegram&&window.Telegram.WebApp;
  if(telegram||window.TelegramWebviewProxy){
    var browserLink=el('a','btn btn--secondary','Открыть в браузере для скачивания');
    browserLink.href=new URL('/connect/join.html',location.origin).href;browserLink.target='_blank';browserLink.rel='noopener noreferrer';
    browserLink.addEventListener('click',function(e){if(telegram&&telegram.openLink){e.preventDefault();telegram.openLink(browserLink.href);}});
    document.querySelector('.vpn-hero').appendChild(browserLink);
  }
  function el(tag,cls,text){var n=document.createElement(tag);if(cls)n.className=cls;if(text!=null)n.textContent=text;return n;}
  function message(text){var n=document.getElementById('download-status');n.hidden=false;n.textContent=text;}
  function icon(name){
    var svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
    svg.setAttribute('viewBox','0 0 24 24');svg.setAttribute('aria-hidden','true');
    var path=document.createElementNS('http://www.w3.org/2000/svg','path');
    path.setAttribute('d',name==='download'?'M12 3v12M7 10l5 5 5-5M5 16v5h14v-5':'M5 12h14M14 7l5 5-5 5');
    svg.appendChild(path);return svg;
  }
  function country(server){
    var id=String(server.alt_of||server.host_group||server.id).toLowerCase().split('-')[0];
    var known={nl:['NL','Нидерланды'],fi:['FI','Финляндия'],us:['US','США'],usa:['US','США'],tr:['TR','Турция']};
    return known[id]||[String(server.id).slice(0,2).toUpperCase(),server.label||server.id];
  }
  function metrics(server,card){
    var h=server.health||{}, latency=h.latency||server.latency||{}, local=latency.local===true||latency.scope==='local';
    var measured=!staleCatalog&&typeof latency.ms==='number'&&Number.isFinite(latency.ms)&&!local;
    var block=el('div','vpn-latency'), value=el('p','vpn-latency-value',staleCatalog?'—':local?'Локально':measured?String(Math.round(latency.ms)):'—');
    if(measured)value.appendChild(el('span','','мс'));
    block.appendChild(value);block.appendChild(el('p','vpn-latency-label',local&&!staleCatalog?'Сам NL-монитор':'От NL-монитора'));card.appendChild(block);
    var meta=el('div','vpn-card-meta');
    meta.appendChild(el('span','',Number.isInteger(server.vpn_port)?'UDP '+server.vpn_port:'UDP'));
    card.appendChild(meta);
  }
  function cardFor(server,data){
    var h=catalog.status(server), place=country(server), card=el('li','vpn-server');
    var labels={online:'Работает',ready:'Готов',degraded:'Ограничения',maintenance:'Отключён',unavailable:'Недоступен',unknown:'Не подтверждён'};
    var state=staleCatalog?'unknown':h.state;
    card.dataset.state=state;
    var top=el('div','vpn-card-top'), code=el('span','vpn-country-code',place[0]);code.setAttribute('aria-hidden','true');top.appendChild(code);
    var status=el('span','server-health server-health--'+state,labels[state]||labels.unknown);
    if(!staleCatalog&&h.checked)status.title='Проверено '+new Date(h.checked*1000).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'});
    top.appendChild(status);card.appendChild(top);
    card.appendChild(el('h3','',place[1]));
    if(server.alt_port)card.appendChild(el('p','vpn-card-note','Альтернативный порт'));
    metrics(server,card);
    var button=el('button','btn btn--primary',busy&&activeServer===server.id?'Готовим…':'Скачать профиль');
    button.type='button';button.disabled=busy||!catalog.selectable(server)||data.public_access===false;button.dataset.focusKey=server.id;
    button.setAttribute('aria-label','Скачать профиль: '+place[1]+(server.alt_port?', UDP '+server.vpn_port:''));
    button.appendChild(icon('download'));button.addEventListener('click',function(){download(server,false);});card.appendChild(button);
    if(h.detail&&!staleCatalog){
      var notice=el('details','vpn-server-notice'), summary=el('summary','','Об ограничениях');summary.dataset.focusKey=server.id+'-notice';notice.appendChild(summary);notice.appendChild(el('p','',h.detail));card.insertBefore(notice,button);
    }
    return card;
  }
  function render(data){
    current=data;catalog.support(data.support||{});
    var servers=data.servers||[], oldFocus=document.activeElement&&document.activeElement.dataset.focusKey, cards=[], alternateCards=[];
    var rank={NL:0,FI:1,US:2,TR:3};
    var openedNotices=Array.from(document.querySelectorAll('.vpn-server-notice[open]')).map(function(n){return n.closest('.vpn-server').dataset.serverId;});
    servers.slice().sort(function(a,b){return (rank[country(a)[0]]===undefined?99:rank[country(a)[0]])-(rank[country(b)[0]]===undefined?99:rank[country(b)[0]]);}).forEach(function(server){
      var card=cardFor(server,data);card.dataset.serverId=server.id;
      if(openedNotices.indexOf(server.id)>=0&&card.querySelector('.vpn-server-notice'))card.querySelector('.vpn-server-notice').open=true;
      (server.alt_port||server.alt_of?alternateCards:cards).push(card);
    });
    grid.replaceChildren.apply(grid,cards);
    grid.setAttribute('aria-busy','false');
    if(!cards.length)grid.appendChild(el('li','vpn-empty','Список серверов пока недоступен.'));
    document.getElementById('alternate-grid').replaceChildren.apply(document.getElementById('alternate-grid'),alternateCards);
    if(oldFocus)Array.from(document.querySelectorAll('[data-focus-key]')).some(function(b){if(b.dataset.focusKey===oldFocus){b.focus();return true;}return false;});
    var select=document.getElementById('extra-server'), chosen=select.value;
    select.replaceChildren();
    servers.filter(catalog.selectable).forEach(function(server){var option=el('option','',server.display||server.label);option.value=server.id;select.appendChild(option);});
    if(servers.some(function(s){return s.id===chosen&&catalog.selectable(s);}))select.value=chosen;
    document.getElementById('extra-profile').disabled=busy||!select.value||data.public_access===false;
    var checked=servers.map(function(s){return catalog.status(s).checked;}).filter(function(t){return typeof t==='number'&&Number.isFinite(t);});
    document.getElementById('network-stats').textContent=staleCatalog?'Нет свежих данных':checked.length?'Проверено '+new Date(Math.min.apply(Math,checked)*1000).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'}):'Статус не подтверждён';
    document.getElementById('monitor-note').textContent='Задержка — от монитора в NL, не с вашего устройства.';
    document.getElementById('catalog-error').hidden=!staleCatalog;
  }
  function stale(){staleCatalog=true;var n=document.getElementById('catalog-error');n.hidden=false;n.textContent='Не удалось обновить состояние. Попробуйте ещё раз.';if(current)render(current);else{grid.setAttribute('aria-busy','false');document.getElementById('network-stats').textContent='Нет свежих данных';}}
  async function refresh(){
    if(loading)return;loading=true;document.getElementById('refresh').disabled=true;
    try{var r=await fetch('/api/awg/servers?include_unavailable=true',{cache:'no-store',credentials:'omit',signal:AbortSignal.timeout(15000)});if(!r.ok)throw new Error('catalog');var data=await r.json();staleCatalog=false;render(data);}catch(e){stale();}
    finally{loading=false;document.getElementById('refresh').disabled=false;}
  }
  async function download(server,fresh){
    if(busy)return;
    if(fresh&&!window.confirm('Создать новый личный профиль для отдельного устройства? Уже скачанные профили продолжат работать.'))return;
    busy=true;activeServer=server.id;if(current)render(current);message('Готовим профиль. Это может занять до минуты.');
    try{
      var identity=await fetch('/api/public/awg/device',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({new_device:fresh}),signal:AbortSignal.timeout(15000)});
      if(!identity.ok){var identityDetail;try{identityDetail=(await identity.json()).detail;}catch(e){}throw new Error(identityDetail||'Не удалось создать профиль. Попробуйте позднее.');}
      var response=await fetch('/api/public/awg/config',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({server_id:server.id}),signal:AbortSignal.timeout(60000)});
      if(!response.ok){var detail;try{detail=(await response.json()).detail;}catch(e){}throw new Error(typeof detail==='string'?detail:response.status===429?'Слишком много запросов подряд. Подождите несколько минут и попробуйте снова.':'Не удалось выдать профиль. Попробуйте другой сервер.');}
      var blob=await response.blob(), url=URL.createObjectURL(blob), a=el('a','');a.href=url;a.download='FVPN-'+server.id.replace(/[^a-z0-9-]/gi,'').slice(0,6)+'.conf';document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(url);},60000);
      message('Откройте скачанный файл в AmneziaWG. Нет файла? Повторите в обычном браузере.');
    }catch(e){message(e.name==='TimeoutError'?'Сервер не успел ответить. Повторите скачивание: тот же профиль будет использован повторно.':e.message||'Нет связи. Попробуйте ещё раз.');}
    finally{busy=false;activeServer=null;if(current)render(current);}
  }
  document.getElementById('refresh').addEventListener('click',refresh);
  document.getElementById('extra-profile').addEventListener('click',function(){var id=document.getElementById('extra-server').value,server=current&&current.servers.find(function(s){return s.id===id;});if(server)download(server,true);});
  document.querySelector('.vpn-intro .vpn-help-link').addEventListener('click',function(){document.getElementById('how').open=true;});
  document.addEventListener('fodder:catalog',function(e){staleCatalog=false;render(e.detail);});
  document.addEventListener('fodder:catalog-error',stale);
  catalog.support({});catalog.watch();
})();
