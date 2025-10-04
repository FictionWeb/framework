function useState(initialValue) {
  let value = initialValue;
  const listeners = new Set();

  return {
    get: () => value,
    set: (newValue) => {
      value = newValue;
      listeners.forEach((fn) => fn(value));
    },
    subscribe: (fn) => {
      listeners.add(fn);
      fn(value);
      return () => listeners.delete(fn);
    }
  };
}
const stateRegistry = {};

function bindState(state, key) {
  state.subscribe((value) => {
    document.querySelectorAll(`[data-bind="${key}"]`).forEach((el) => {
      el.textContent = value;
    });
  });
}

function isJSON(str) {
    try {
        return (JSON.parse(str) && !!str);
    } catch (e) {
        return false;
    }
}

function serverAction(action, data, callback) {
 // const csrf = "$csrf";
 let contentype = 'text/plain';
 if (data && isJSON(data)) contentype = 'application/json'
  fetch('/', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Fiction-Action': action.replace('/',''),
      'Content-Type': contentype
  //    'X-CSRF-Token': csrf
    }, 
    body: data
  }).then(res => { 
  const contentType = res.headers.get("content-type");
  if (contentType && contentType.indexOf("application/json") !== -1) {
    res.json().then(output => callback(output))
} else {
  console.log(res)
}}).catch(err => console.error('Request failed:', err));
}
