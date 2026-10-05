/* Short ASCII names avoid browsers' duplicate-file suffixes. No profile data here. */
(function () {
  'use strict';
  window.FodderProfileFile = {
    name: function (server) {
      var suffix;
      if (window.crypto && window.crypto.getRandomValues) {
        var bytes = new Uint8Array(3); window.crypto.getRandomValues(bytes);
        suffix = Array.from(bytes, function (b) { return b.toString(16).padStart(2, '0'); }).join('');
      } else { suffix = Date.now().toString(36).slice(-6); }
      var region = String(server || 'vpn').replace(/[^a-z0-9-]/gi, '').split('-')[0].slice(0, 3) || 'vpn';
      return 'FVPN-' + region + '-' + suffix + '.conf';
    },
    save: function (blob, name) {
      var url = URL.createObjectURL(blob), a = document.createElement('a');
      a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
    }
  };
}());
