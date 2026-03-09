# Atividade RSA com TCP

## Descrição
Este projeto implementa uma comunicação TCP entre cliente e servidor em máquinas distintas, com análise do tráfego no Wireshark e proteção do fluxo utilizando criptografia RSA autoral com chaves assimétricas de 4096 bits.

Também foi utilizada a lógica da Cifra de César no processamento da mensagem antes da criptografia RSA.

## Ambiente utilizado
- **Servidor (Bob):** VM Kali Linux
- **Cliente (Alice):** Notebook Windows
- **IP do servidor:** `192.168.1.16`
- **Porta TCP:** `1300`

## Arquivos do projeto
- `Simple_tcpServer.py` -> versão original sem criptografia
- `Simple_tcpClient.py` -> versão original sem criptografia
- `rsa_tcpServer.py` -> versão com RSA + Cifra de César
- `rsa_tcpClient.py` -> versão com RSA + Cifra de César
- `primo_hyper.py` -> código de apoio para lógica eficiente de primalidade

## Etapa 1 - Teste da comunicação simples
Primeiramente, foi testada a comunicação entre cliente e servidor utilizando os arquivos originais `Simple_tcpServer.py` e `Simple_tcpClient.py`.

### Resultado
A conexão TCP foi estabelecida com sucesso entre as duas máquinas e o fluxo pôde ser visualizado no Wireshark.

### Observação
Na versão original, a mensagem trafega em texto claro, podendo ser lida diretamente na captura de pacotes.

## Etapa 2 - Implementação do RSA
Foi implementado um RSA autoral com:
- geração de números primos grandes
- cálculo da chave pública e privada
- criptografia da mensagem no cliente
- descriptografia da mensagem no servidor

Além disso, foi aplicada a **Cifra de César** antes da criptografia RSA e sua reversão após a descriptografia.

## Etapa 3 - Chaves de 4096 bits
As chaves RSA foram geradas com tamanho de **4096 bits**, conforme solicitado na atividade.

A geração dos primos foi baseada em uma abordagem eficiente inspirada no arquivo `primo_hyper.py`, utilizando teste probabilístico de primalidade do tipo Miller-Rabin.

## Funcionamento do sistema
1. O servidor gera as chaves RSA de 4096 bits.
2. O cliente conecta ao servidor.
3. O servidor envia a chave pública ao cliente.
4. O cliente lê a mensagem digitada.
5. O cliente aplica a Cifra de César.
6. O cliente criptografa a mensagem com RSA.
7. O cliente envia o ciphertext ao servidor.
8. O servidor descriptografa a mensagem com a chave privada.
9. O servidor desfaz a Cifra de César.
10. O servidor recupera a mensagem original.

## Como executar

### Servidor
No Kali Linux:

```bash
cd ~/rsa_tcp
python3 rsa_tcpServer.py