// Service worker minimo: solo maneja notificaciones push. No cachea nada
// (no es una PWA offline completa, solo el canal de notificaciones).
self.addEventListener('push', (event) => {
  let data = {};
  try { data = event.data.json(); } catch(e) {}
  const title = data.title || 'Gerencia Sureste';
  const options = {
    body: data.body || 'Tienes un mensaje nuevo',
    icon: '/icon-192.png',
    data: { channelId: data.channelId },
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window' }).then((clientList) => {
      for (const client of clientList) {
        if (client.url.includes('/chat.html') && 'focus' in client) return client.focus();
      }
      if (clients.openWindow) return clients.openWindow('/chat.html');
    })
  );
});
