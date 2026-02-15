import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import { execFile } from "child_process";

/**
 * Resolve the path to the dcert-mcp binary.
 *
 * Priority:
 * 1. User-configured path via `dcert.mcp.path` setting
 * 2. Binary found on system PATH
 */
function resolveBinaryPath(): string {
  const config = vscode.workspace.getConfiguration("dcert.mcp");
  const userPath = config.get<string>("path", "");
  if (userPath && fs.existsSync(userPath)) {
    return userPath;
  }
  // Fall back to PATH lookup — the McpStdioServerDefinition will
  // resolve the command via PATH automatically when given just a name.
  return "dcert-mcp";
}

/**
 * Check if dcert-mcp is reachable and log its version.
 */
function checkBinaryAvailable(binaryPath: string): Promise<boolean> {
  return new Promise((resolve) => {
    execFile(binaryPath, ["--version"], { timeout: 5000 }, (error, stdout) => {
      if (error) {
        resolve(false);
      } else {
        const version = stdout.trim().split("\n")[0] ?? "";
        console.log(`dcert-mcp found: ${version}`);
        resolve(true);
      }
    });
  });
}

export async function activate(
  context: vscode.ExtensionContext
): Promise<void> {
  const binaryPath = resolveBinaryPath();

  const available = await checkBinaryAvailable(binaryPath);
  if (!available) {
    const install = "Install with Homebrew";
    const configure = "Configure Path";
    const choice = await vscode.window.showWarningMessage(
      "dcert-mcp binary not found. Install it to enable TLS certificate analysis tools.",
      install,
      configure
    );
    if (choice === install) {
      const terminal = vscode.window.createTerminal("Install dcert");
      terminal.sendText("brew tap SCGIS-Wales/tap && brew install dcert");
      terminal.show();
    } else if (choice === configure) {
      vscode.commands.executeCommand(
        "workbench.action.openSettings",
        "dcert.mcp.path"
      );
    }
  }

  const didChangeEmitter = new vscode.EventEmitter<void>();
  context.subscriptions.push(didChangeEmitter);

  // Re-register when the user changes the binary path setting
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("dcert.mcp.path")) {
        didChangeEmitter.fire();
      }
    })
  );

  context.subscriptions.push(
    vscode.lm.registerMcpServerDefinitionProvider("dcert-mcp", {
      onDidChangeMcpServerDefinitions: didChangeEmitter.event,

      provideMcpServerDefinitions:
        async (): Promise<vscode.McpServerDefinition[]> => {
          const binary = resolveBinaryPath();
          return [
            new vscode.McpStdioServerDefinition(
              "dcert-mcp",
              binary,
              [],
              undefined,
              context.extension.packageJSON.version
            ),
          ];
        },
    })
  );
}

export function deactivate(): void {
  // Cleanup handled by disposables
}
