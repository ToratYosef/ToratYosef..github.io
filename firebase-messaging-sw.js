importScripts('https://www.gstatic.com/firebasejs/11.9.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/11.9.0/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey: 'AIzaSyAVSkxnzvt6jJOSgQcaRFX7tfnPPPeYQvY',
  authDomain: 'torat-yose.firebaseapp.com',
  projectId: 'torat-yose',
  storageBucket: 'torat-yose.appspot.com',
  messagingSenderId: '1054733969512',
  appId: '1:1054733969512:web:9703846085ab15d08c73dd'
});

firebase.messaging();
