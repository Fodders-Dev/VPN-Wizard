/* Personal configuration downloads are explicit POSTs, never cached. */
(function(){
  'use strict';
  var catalog=window.FodderCatalog, grid=document.getElementById('server-grid');
  var busy=false, current=null, loading=false, staleCatalog=false, activeServer=null, activeFormat=null;
  var qrDialog=document.getElementById('profile-qr-dialog'), qrImage=document.getElementById('profile-qr'), qrUrl=null, qrFocusKey=null;
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
    path.setAttribute('d',name==='download'?'M12 3v12M7 10l5 5 5-5M5 16v5h14v-5':name==='qr'?'M3 3h6v6H3zM15 3h6v6h-6zM3 15h6v6H3zM15 15h3v3h3v3h-6z':'M5 12h14M14 7l5 5-5 5');
    svg.appendChild(path);return svg;
  }
  function country(server){
    var id=String(server.alt_of||server.host_group||server.id).toLowerCase().split('-')[0];
    var known={nl:['NL','Нидерланды'],fi:['FI','Финляндия'],us:['US','США'],usa:['US','США'],tr:['TR','Турция']};
    return known[id]||[String(server.id).slice(0,2).toUpperCase(),server.label||server.id];
  }
  function stateOf(server){return server.enabled===false?'maintenance':staleCatalog?'unknown':catalog.status(server).state;}
  function caution(state){return {degraded:'Не рекомендуем: у части пользователей нет соединения. Выберите другой сервер.',unavailable:'Не работает. Профили временно недоступны — выберите другой сервер.',maintenance:'Сервер отключён. Выберите другой сервер.',unknown:'Работа не подтверждена. Лучше выбрать сервер со статусом «Работает».'}[state]||'';}
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
    var labels={online:'Работает',ready:'Готов',degraded:'Не рекомендуем',maintenance:'Отключён',unavailable:'Не работает',unknown:'Не подтверждён'};
    var state=stateOf(server);
    card.dataset.state=state;
    var top=el('div','vpn-card-top'), code=el('span','vpn-country-code',place[0]);code.setAttribute('aria-hidden','true');top.appendChild(code);
    var status=el('span','server-health server-health--'+state,labels[state]||labels.unknown);
    if(!staleCatalog&&h.checked)status.title='Проверено '+new Date(h.checked*1000).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'});
    top.appendChild(status);card.appendChild(top);
    card.appendChild(el('h3','',place[1]));
    if(server.alt_port)card.appendChild(el('p','vpn-card-note','Альтернативный порт'));
    metrics(server,card);
    var warning=caution(state);
    if(warning){var warningNote=el('p','vpn-server-warning',warning);warningNote.id='server-warning-'+server.id.replace(/[^a-z0-9-]/gi,'');card.appendChild(warningNote);}
    var actions=el('div','vpn-profile-actions');
    var button=el('button','btn btn--primary',busy&&activeServer===server.id&&activeFormat!=='qr'?'Готовим…':state==='maintenance'?'Отключён':state==='unavailable'?'Недоступен':warning?'Всё равно скачать':'Скачать профиль');
    button.type='button';button.disabled=busy||!catalog.selectable(server)||data.public_access===false;button.dataset.focusKey=server.id;
    button.setAttribute('aria-label','Скачать профиль: '+place[1]+(server.alt_port?', UDP '+server.vpn_port:''));
    if(warning)button.setAttribute('aria-describedby',warningNote.id);
    button.appendChild(icon('download'));button.addEventListener('click',function(){download(server,false,'config');});actions.appendChild(button);
    var qrButton=el('button','btn btn--qr',busy&&activeServer===server.id&&activeFormat==='qr'?'…':'QR');
    qrButton.type='button';qrButton.disabled=button.disabled;qrButton.dataset.focusKey=server.id+'-qr';
    qrButton.setAttribute('aria-label','QR-код профиля: '+place[1]+(server.alt_port?', UDP '+server.vpn_port:''));qrButton.setAttribute('aria-haspopup','dialog');
    if(warning)qrButton.setAttribute('aria-describedby',warningNote.id);
    qrButton.appendChild(icon('qr'));qrButton.addEventListener('click',function(){download(server,false,'qr');});actions.appendChild(qrButton);
    if(h.detail&&!staleCatalog){
      var notice=el('details','vpn-server-notice'), summary=el('summary','','Подробнее');summary.dataset.focusKey=server.id+'-notice';notice.appendChild(summary);notice.appendChild(el('p','',h.detail));card.appendChild(notice);
    }
    card.appendChild(actions);
    return card;
  }
  function render(data){
    current=data;catalog.support(data.support||{});
    var servers=data.servers||[], oldFocus=document.activeElement&&document.activeElement.dataset.focusKey, cards=[], alternateCards=[];
    var rank={NL:0,FI:1,US:2,TR:3};
    var openedNotices=Array.from(document.querySelectorAll('.vpn-server-notice[open]')).map(function(n){return n.closest('.vpn-server').dataset.serverId;});
    var healthRank={online:0,ready:0,unknown:1,degraded:2,unavailable:3,maintenance:3};
    servers.slice().sort(function(a,b){return (healthRank[stateOf(a)]??1)-(healthRank[stateOf(b)]??1)||(rank[country(a)[0]]===undefined?99:rank[country(a)[0]])-(rank[country(b)[0]]===undefined?99:rank[country(b)[0]]);}).forEach(function(server){
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
    servers.filter(catalog.selectable).forEach(function(server){var option=el('option','',(server.display||server.label)+(caution(stateOf(server))?' — не рекомендуем':''));option.value=server.id;select.appendChild(option);});
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
  async function download(server,fresh,format){
    if(busy)return;
    server=current&&current.servers.find(function(s){return s.id===server.id;});
    if(!server||!catalog.selectable(server)||current.public_access===false)return;
    var warning=caution(stateOf(server));
    if(warning&&!window.confirm(country(server)[1]+': '+warning+'\n\nВсё равно получить профиль?'))return;
    if(fresh&&!window.confirm('Создать новый личный профиль для отдельного устройства? Уже скачанные профили продолжат работать.'))return;
    format=format||'config';busy=true;activeServer=server.id;activeFormat=format;
    if(format==='qr'){
      qrFocusKey=server.id+'-qr';document.getElementById('profile-qr-title').textContent='QR · '+country(server)[1]+(server.alt_port?' · UDP '+server.vpn_port:'');
      document.getElementById('profile-qr-status').textContent='Готовим QR-код. Это может занять до минуты.';qrImage.hidden=true;qrDialog.showModal();
    }
    if(current)render(current);message('Готовим профиль. Это может занять до минуты.');
    try{
      var identity=await fetch('/api/public/awg/device',{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json'},body:JSON.stringify({new_device:fresh}),signal:AbortSignal.timeout(15000)});
      if(!identity.ok){var identityDetail;try{identityDetail=(await identity.json()).detail;}catch(e){}throw new Error(identityDetail||'Не удалось создать профиль. Попробуйте позднее.');}
      var response=await fetch(format==='qr'?'/api/public/awg/qr':'/api/public/awg/config',{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json'},body:JSON.stringify({server_id:server.id}),signal:AbortSignal.timeout(60000)});
      if(!response.ok){var detail;try{detail=(await response.json()).detail;}catch(e){}throw new Error(typeof detail==='string'?detail:response.status===429?'Слишком много запросов подряд. Подождите несколько минут и попробуйте снова.':'Не удалось выдать профиль. Попробуйте другой сервер.');}
      var blob=await response.blob();
      if(format==='qr'){
        if(qrDialog.open){qrUrl=URL.createObjectURL(blob);qrImage.src=qrUrl;qrImage.hidden=false;document.getElementById('profile-qr-status').textContent='В AmneziaWG: + → Сканировать QR-код.';}
        message('QR и скачанный файл используют один личный профиль.');
      }else{
        var url=URL.createObjectURL(blob), a=el('a','');a.href=url;a.download='FVPN-'+server.id.replace(/[^a-z0-9-]/gi,'').slice(0,6)+'.conf';document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(url);},60000);
        message('Откройте скачанный файл в AmneziaWG. Нет файла? Повторите в обычном браузере.');
      }
    }catch(e){var error=e.name==='TimeoutError'?'Сервер не успел ответить. Повторите: тот же профиль будет использован повторно.':e.message||'Нет связи. Попробуйте ещё раз.';message(error);if(format==='qr'&&qrDialog.open)document.getElementById('profile-qr-status').textContent=error;}
    finally{busy=false;activeServer=null;activeFormat=null;if(current)render(current);}
  }
  qrDialog.addEventListener('close',function(){if(qrUrl){URL.revokeObjectURL(qrUrl);qrUrl=null;}qrImage.removeAttribute('src');qrImage.hidden=true;Array.from(document.querySelectorAll('[data-focus-key]')).some(function(n){if(n.dataset.focusKey===qrFocusKey){n.focus();return true;}return false;});});
  qrImage.addEventListener('error',function(){qrImage.hidden=true;document.getElementById('profile-qr-status').textContent='Не удалось показать QR-код. Закройте окно и попробуйте снова.';});
  if(!('closedBy' in HTMLDialogElement.prototype))qrDialog.addEventListener('click',function(e){if(e.target!==qrDialog)return;var r=qrDialog.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)qrDialog.close();});
  document.getElementById('refresh').addEventListener('click',refresh);
  document.getElementById('extra-profile').addEventListener('click',function(){var id=document.getElementById('extra-server').value,server=current&&current.servers.find(function(s){return s.id===id;});if(server)download(server,true);});
  document.querySelector('.vpn-intro .vpn-help-link').addEventListener('click',function(){document.getElementById('how').open=true;});
  document.addEventListener('fodder:catalog',function(e){staleCatalog=false;render(e.detail);});
  document.addEventListener('fodder:catalog-error',stale);
  catalog.support({});catalog.watch();
})();
