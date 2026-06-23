const apiKeyInput = document.getElementById('apiKey') as HTMLInputElement;
const saveKeyButton = document.getElementById('saveKey') as HTMLButtonElement;
const createExeButton = document.getElementById(
  'createExe'
) as HTMLButtonElement;
const keyStatus = document.getElementById('keyStatus') as HTMLParagraphElement;
const scanOutput = document.getElementById('scanOutput') as HTMLDivElement;

const api = (window as any).electronApi;

async function onCreateExe() {
  scanOutput.textContent =
    'Создание standalone EXE...\nЭто может занять минуту или две.';
  const key = apiKeyInput.value.trim();
  if (!key) {
    scanOutput.textContent = 'Ошибка: Сначала введите и сохраните ключ.';
    return;
  }

  const result = await api.createExe(key);
  if (result.success) {
    scanOutput.textContent = `Успех!\nEXE файл создан:\n${result.path}\n\nВы можете отправить этот файл другим пользователям для проверки их системы.`;
  } else {
    scanOutput.textContent = `Ошибка создания EXE: ${result.error}`;
  }
}

async function readApiKey(): Promise<string | undefined> {
  return await api.readApiKey();
}

async function saveApiKey(key: string) {
  return await api.saveApiKey(key);
}

async function onSaveKey() {
  const key = apiKeyInput.value.trim();
  if (!key) {
    keyStatus.textContent = 'Введите действительный ключ.';
    return;
  }

  await saveApiKey(key);
  keyStatus.textContent = 'Ключ сохранён. Можно генерировать exe';
}

async function init() {
  const storedKey = await readApiKey();
  if (storedKey) {
    apiKeyInput.value = storedKey;
    keyStatus.textContent = 'Ключ уже сохранён.';
  }

  saveKeyButton.addEventListener('click', onSaveKey);
  createExeButton.addEventListener('click', onCreateExe);
}

init().catch((error) => {
  scanOutput.textContent = `Ошибка инициализации: ${error?.message || error}`;
});
