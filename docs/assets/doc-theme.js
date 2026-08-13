document.querySelectorAll('.copy-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const pre = btn.closest('.codewrap').querySelector('pre');
    navigator.clipboard.writeText(pre.innerText).then(() => {
      btn.textContent = 'Copied!'; btn.classList.add('done');
      setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('done'); }, 1500);
    }).catch(() => { btn.textContent = 'Failed'; setTimeout(() => { btn.textContent = 'Copy'; }, 1500); });
  });
});
