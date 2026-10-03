/* Personal configuration downloads are explicit POSTs, never cached. */
(function(){
  'use strict';
  var catalog=window.FodderCatalog, grid=document.getElementById('server-grid');
  var busy=false, current=null, loading=false;
  var telegram=window.Telegram&&window.Telegram.WebApp;
  if(telegram||window.TelegramWebviewProxy){
    var browserLink=el('a','btn btn--secondary','Открыть в браузере для скачивания');
    browserLink.href=new URL('/connect/join.html',location.origin).href;browserLink.target='_blank';browserLink.rel='noopener noreferrer';
    browserLink.addEventListener('click',function(e){if(telegram&&telegram.openLink){e.preventDefault();telegram.openLink(browserLink.href);}});
    document.querySelector('.vpn-hero').appendChild(browserLink);
  }
  function el(tag,cls,text){var n=document.createElement(tag);if(cls)n.className=cls;if(text!=null)n.textContent=text;return n;}
  function message(text){var n=document.getElementById('download-status');n.hidden=false;n.textContent=text;}
  function metrics(server){
    var h=server.health||{}, parts=['UDP '+server.vpn_port], latency=h.latency||server.latency||{};
    if(typeof latency.ms==='number')parts.push(Math.round(latency.ms)+' мс · от NL-монитора');
    else parts.push(latency.scope==='local'?'Локально для NL-монитора':'Пинг пока не измерен');
    if(typeof h.recent_connections==='number')parts.push(h.recent_connections+' подключений за 5 мин');
    return parts.join(' · ');
  }
  function render(data){
    current=data;catalog.support(data.support||{});
    var servers=data.servers||[], oldFocus=document.activeElement&&document.activeElement.dataset.focusKey, cards=[];
    servers.forEach(function(server){
      var h=catalog.status(server), card=el('li','vpn-server');
      card.appendChild(el('h3','',server.display||server.label||server.id));
      if(server.alt_port)card.appendChild(el('p','vpn-kicker','Альтернативный порт · тот же сервер'));
      card.appendChild(el('p','server-health server-health--'+h.state,h.label));
      card.appendChild(el('p','t-sm dim',h.detail||'Состояние проверяется автоматически каждые 2 минуты.'));
      card.appendChild(el('p','vpn-server__metrics',metrics(server)));
      card.appendChild(el('p','t-sm mute',h.checked?'Проверено '+new Date(h.checked*1000).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'}):'Нет свежего замера — подключение не подтверждено.'));
      var button=el('button','btn btn--primary','Скачать профиль');button.type='button';button.disabled=busy||!catalog.selectable(server)||data.public_access===false;button.dataset.focusKey=server.id;
      button.setAttribute('aria-label','Скачать профиль: '+(server.display||server.label||server.id));
      button.addEventListener('click',function(){download(server,false);});card.appendChild(button);
      if(catalog.selectable(server)){
        var fresh=el('button','btn btn--secondary','Создать отдельный профиль');fresh.type='button';fresh.disabled=busy||data.public_access===false;fresh.dataset.focusKey=server.id+'-new';
        fresh.setAttribute('aria-label','Создать отдельный профиль: '+(server.display||server.label||server.id));fresh.addEventListener('click',function(){download(server,true);});card.appendChild(fresh);
      }
      cards.push(card);
    });
    grid.replaceChildren.apply(grid,cards);
    if(oldFocus)Array.from(grid.querySelectorAll('button')).some(function(b){if(b.dataset.focusKey===oldFocus){b.focus();return true;}return false;});
    var unique=servers.filter(function(s){return !s.alt_of;}), online=unique.filter(function(s){return ['online','ready'].indexOf(catalog.status(s).state)>=0;}).length;
    var partial=unique.filter(function(s){return catalog.status(s).state==='degraded';}).length, stats=document.getElementById('network-stats');stats.replaceChildren();
    [[unique.length,'серверов в каталоге'],[online,'без известных проблем'],[partial,'с ограничениями доступа']].forEach(function(pair){var p=el('p','');p.appendChild(el('strong','',String(pair[0])));p.appendChild(el('span','dim',pair[1]));stats.appendChild(p);});
    document.getElementById('monitor-note').textContent=(data.status_note||'Проверка серверов не гарантирует доступность у вашего оператора.')+' Пинг — замер от NL-монитора, не от вашего устройства. Альтернативные порты используют тот же сервер.';
    document.getElementById('catalog-error').hidden=true;
  }
  function stale(){var n=document.getElementById('catalog-error');n.hidden=false;n.textContent='Нет свежего состояния серверов. Нажмите «Обновить».';grid.querySelectorAll('.server-health').forEach(function(p){p.textContent='Статус устарел';p.className='server-health';});}
  async function refresh(){
    if(loading)return;loading=true;document.getElementById('refresh').disabled=true;
    try{var r=await fetch('/api/awg/servers?include_unavailable=true',{cache:'no-store',credentials:'omit',signal:AbortSignal.timeout(15000)});if(!r.ok)throw new Error('catalog');render(await r.json());}catch(e){stale();}
    finally{loading=false;document.getElementById('refresh').disabled=false;}
  }
  async function download(server,fresh){
    if(busy)return;
    if(fresh&&!window.confirm('Создать новый личный профиль для отдельного устройства? Уже скачанные профили продолжат работать.'))return;
    busy=true;if(current)render(current);message('Готовим личный профиль '+(server.label||server.id)+'… Не закрывайте страницу.');
    try{
      var identity=await fetch('/api/public/awg/device',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({new_device:fresh}),signal:AbortSignal.timeout(15000)});
      if(!identity.ok){var identityDetail;try{identityDetail=(await identity.json()).detail;}catch(e){}throw new Error(identityDetail||'Не удалось создать профиль. Попробуйте позднее.');}
      var response=await fetch('/api/public/awg/config',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({server_id:server.id}),signal:AbortSignal.timeout(60000)});
      if(!response.ok){var detail;try{detail=(await response.json()).detail;}catch(e){}throw new Error(typeof detail==='string'?detail:response.status===429?'Слишком много запросов подряд. Подождите несколько минут и попробуйте снова.':'Не удалось выдать профиль. Попробуйте другой сервер.');}
      var blob=await response.blob(), url=URL.createObjectURL(blob), a=el('a','');a.href=url;a.download='FVPN-'+server.id.replace(/[^a-z0-9-]/gi,'').slice(0,6)+'.conf';document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(url);},60000);
      message('Скачивание отправлено. Импортируйте профиль в AmneziaWG. Если файл не появился (например, внутри Telegram), откройте эту страницу в обычном браузере и повторите. Нет соединения? Выберите другой сервер.');
    }catch(e){message(e.name==='TimeoutError'?'Сервер не успел ответить. Повторите скачивание: тот же профиль будет использован повторно.':e.message||'Нет связи. Попробуйте ещё раз.');}
    finally{busy=false;if(current)render(current);}
  }
  document.getElementById('refresh').addEventListener('click',refresh);
  document.addEventListener('fodder:catalog',function(e){render(e.detail);});
  document.addEventListener('fodder:catalog-error',stale);
  refresh();catalog.watch();
})();
