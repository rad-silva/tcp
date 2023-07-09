import asyncio
import random
import time
from tcputils import *


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)


    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback


    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, flags, \
            window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
    
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao)
           
            # Define o número de reconhecimento: ao setar "conexao.ack_no" como "seq_no + 1",
            # o receptor está dizendo ao cliente que recebeu com sucesso tudo até o byte "seq_no".
            # Define um número de sequencia inicial aleatório para o receptor
            conexao.ack_no = seq_no + 1
            conexao.seq_no = random.randint(0, 0xffff)
            flags = FLAGS_SYN | FLAGS_ACK

            header = make_header(dst_port, src_port, conexao.seq_no, conexao.ack_no, flags)
            segment = fix_checksum(header, dst_addr, src_addr)
            self.rede.enviar(segment, src_addr)

            # Atualiza número do byte para o próximo segmento que será enviado
            conexao.seq_no += 1

            if self.callback:
                self.callback(conexao)
    
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)

        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None

        # VER PAG 172 DO LIVRO
        # O número de reconhecimento que o hospedeiro A atribui a seu segmento é o número
        # de sequência do próximo byte que ele estiver aguardando do hospedeiro B

        self.seq_no = None      # número do primeiro byte do segmento que será enviado
        self.ack_no = None      # número de reconhecimento (número de sequência do próximo byte a ser recebido)
        self.next_seq_no = None
        
        self.timer = None
        self.timer_active = False
        self.not_ack_seqments = []

        self.estimatedRTT = None
        self.sampleRTT = None
        self.devRTT = None
        self.timeoutInterval = 1
        #asyncio.get_event_loop().call_later(1, self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        #self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida


    # Se existirem pacotes sem confirmação, reenvia os
    def timeout(self):
        if self.not_ack_seqments:
            segment = self.not_ack_seqments[0][0]
            src_addr = self.not_ack_seqments[0][1]

            self.servidor.rede.enviar(segment, src_addr)

            # self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self.timeout)
            # self.timer_active = True


    def computeTimeoutInterval(self):
        if len(self.not_ack_seqments) == 0:
            return
        
        time_send_seq = self.not_ack_seqments[0][2]
        time_recv_ack = time.time()

        # tempo decorrido entre enviar um segmento e receber o ACK dele.
        self.sampleRTT =  time_recv_ack - time_send_seq

        # Ao medir o primeiro SampleRTT de uma conexão inicializamos os EstimatedRTT e DevRTT
        # com SampleRTT e SampleRTT/2, respectivamente, como sugerido pela RFC 2988.
        if self.estimatedRTT is None:
            self.estimatedRTT = self.sampleRTT
            self.devRTT = self.sampleRTT / 2
        else:
            self.estimatedRTT = 0.875 * self.estimatedRTT + 0.125 * self.sampleRTT
            self.devRTT = 0.75 * self.devRTT + 0.25 * abs(self.sampleRTT - self.estimatedRTT)

        self.timeoutInterval = self.estimatedRTT + 4 * self.devRTT
        print("Timeout: ", self.timeoutInterval)


    # Trata o recebimento de segmentos provenientes da camada de rede.
    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        print('recebido payload: %r' % payload)
        
        # Se o número de sequência recebido for diferente do
        # número de reconhecimento esperado descarta o segmento
        # (duplicado ou fora de ordem)
        if seq_no != self.ack_no:
            print("Segmento com seq_no errado")
            return
        
        # Verifica se o segmento recebido possui a flag FIN (pode vir com outra flag junto)
        # Caso afirmativo, retorna uma confirmação para fechamento da conexão
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            print("Solicitação de fechamento de conexão")

            self.ack_no += 1
            payload = b''
        
        # Verifica se o segmento recebido possui apenas a flag ACK
        # Caso afirmativo, este é apenas uma confirmação da outra ponta
        elif (flags & FLAGS_ACK) == FLAGS_ACK and len(payload) == 0:
            print("Segmento ACK recebido, não é necessário enviar uma resposta.")
            

            if self.not_ack_seqments:
                self.computeTimeoutInterval()

                self.timer.cancel()
                self.timer_active = False
                self.not_ack_seqments.pop(0)

            # se ainda existirem pacotes aguardando confirmação solta o timer
            if self.not_ack_seqments:
                self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self.timeout)
                self.timer_active = True

            return

        # Atualiza o número de reconhecimento indicando que foram recebidos
        # os bytes até "self.ack_no + len(payload)
        self.ack_no += len(payload)
        self.seq_no = ack_no

        self.callback(self, payload)

        # Constrói o pacote de confirmação (ACK) e envia de volta ao remetente
        (src_addr, src_port, dst_addr, dst_port) = self.id_conexao

        header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
        segment = fix_checksum(header, dst_addr, src_addr)

        self.servidor.rede.enviar(segment, src_addr)


    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback


    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        # que você construir para a camada de rede.

        buffer = dados
        (src_addr, src_port, dst_addr, dst_port) = self.id_conexao

        while len(buffer) > 0:
            # Carrega o payload e atualiza o buffer da conexão
            # *MSS é o tamanho do payload de um segmento TCP (em bytes)
            payload = buffer[:MSS]
            buffer = buffer[MSS:]
            
            header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segment = fix_checksum(header + payload, dst_addr, src_addr)

            self.servidor.rede.enviar(segment, src_addr)
            self.seq_no += len(payload)

            time_send_seq = time.time()
            self.not_ack_seqments.append([segment, src_addr, time_send_seq])

            # Inicia o timer após o envio do segmento
            #if not self.timer_active:
            self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self.timeout)
            self.timer_active = True



    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        (src_addr, src_port, dst_addr, dst_port) = self.id_conexao

        header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_FIN)
        segment = fix_checksum(header, dst_addr, src_addr)
        self.servidor.rede.enviar(segment, src_addr)

        del self.servidor.conexoes[self.id_conexao]
