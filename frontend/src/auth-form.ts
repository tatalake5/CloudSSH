import { SSHTerminal, SSHConnectionConfig } from './terminal';

export class ConnectionForm {
  private terminal: SSHTerminal;

  constructor(terminal: SSHTerminal) {
    this.terminal = terminal;
    this.render();
  }

  private render(): void {
    const form = document.getElementById('connection-form')!;

    form.innerHTML = `
      <div class="form-group">
        <label for="host">主机地址</label>
        <input type="text" id="host" placeholder="192.168.1.100 或 example.com" required />
      </div>
      <div class="form-group">
        <label for="port">端口</label>
        <input type="number" id="port" value="22" min="1" max="65535" />
      </div>
      <div class="form-group">
        <label for="username">用户名</label>
        <input type="text" id="username" placeholder="root" required />
      </div>
      <div class="form-group">
        <label for="password">密码</label>
        <input type="password" id="password" required />
      </div>
      <button type="button" id="connect-btn" class="btn-connect">
        连接
      </button>
    `;

    document.getElementById('connect-btn')!.addEventListener('click', () => {
      this.handleConnect();
    });

    form.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.handleConnect();
    });
  }

  private async handleConnect(): Promise<void> {
    const host = (document.getElementById('host') as HTMLInputElement).value;
    const port = parseInt(
      (document.getElementById('port') as HTMLInputElement).value || '22'
    );
    const username = (document.getElementById('username') as HTMLInputElement).value;
    const password = (document.getElementById('password') as HTMLInputElement).value;

    if (!host || !username || !password) {
      alert('请填写所有必填字段');
      return;
    }

    document.getElementById('connection-form')!.style.display = 'none';
    document.getElementById('terminal-container')!.style.display = 'block';
    document.getElementById('toolbar')!.style.display = 'flex';

    document.getElementById('connection-info')!.textContent =
      `${username}@${host}:${port}`;

    this.terminal.mount();

    try {
      await this.terminal.connect({ host, port, username, password });
    } catch (error) {
      document.getElementById('connection-form')!.style.display = 'block';
      document.getElementById('terminal-container')!.style.display = 'none';
      document.getElementById('toolbar')!.style.display = 'none';
      alert('连接失败，请检查连接信息');
    }
  }
}
