import { SSHTerminal } from './terminal';
import { ConnectionForm } from './auth-form';

const terminal = new SSHTerminal('terminal-container');
const form = new ConnectionForm(terminal);

document.getElementById('disconnect-btn')?.addEventListener('click', () => {
  terminal.disconnect();
  document.getElementById('connection-form')!.style.display = 'block';
  document.getElementById('terminal-container')!.style.display = 'none';
  document.getElementById('toolbar')!.style.display = 'none';
});
