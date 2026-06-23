# Cheat Scanner

Windows artifact scanner that inspects AppData folders, Recent/Prefetch artifacts, and registry keys for suspicious cheat client indicators.

## Usage

1. Install dependencies:
   ```bash
   npm install
   ```
2. Run the scanner:
   ```bash
   npm start
   ```

## Notes

- The tool is intended for Windows.
- It uses `reg query` and `systeminfo` to collect registry and install-date data.
- Uses the built-in `ollama-js` library to send the scan summary to Ollama for analysis.
- Set `OLLAMA_MODEL` environment variable to choose a model (default: `llama3.1`).
- Set `OLLAMA_HOST` to override the Ollama host (default: `http://127.0.0.1:11434`).
- Set `OLLAMA_API_KEY` for Ollama Cloud.
