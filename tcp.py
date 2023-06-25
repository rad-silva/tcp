import asyncio
import random
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
        (
            src_port,
            dst_port,
            seq_no,
            ack_no,
            flags,
            window_size,
            checksum,
            urg_ptr
        ) = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
    
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao)
            
            # Define um seq_no aleatório
            conexao.seq_no = random.randint(0, 0xffff)
            conexao.ack_no = seq_no + 1

            header = make_header(dst_port, src_port, conexao.seq_no, conexao.ack_no, FLAGS_SYN | FLAGS_ACK)
            handshake_header = fix_checksum(header, dst_addr, src_addr)
            self.rede.enviar(handshake_header, src_addr)

            # Atualiza o seq_no
            conexao.seq_no += 1
            conexao.prox_seq_no = conexao.seq_no

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

        self.seq_no = None
        self.ack_no = None
        self.prox_seq_no = None
        self.buffer = b''

        self.pacotes_sem_ack = []

        self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        #self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida


    def _exemplo_timer(self):
        if self.pacotes_sem_ack:
            segmento, _, dst_addr, _ = self.pacotes_sem_ack[0]

            # Reenviando pacote
            self.servidor.rede.enviar(segmento, dst_addr)
            self.pacotes_sem_ack[0][3] = None


    # Trata o recebimento de segmentos provenientes da camada de rede.
    # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
    # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.
    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        print('recebido payload: %r' % payload)
        
        (src_addr, src_port, dst_addr, dst_port) = self.id_conexao

        # Verifica se o número de sequência (seq_no) recebido
        # é igual ao número de reconhecimento esperado (self.ack_no)
        # caso afirmativo o segmento está fora de ordem ou duplicado
        if seq_no != self.ack_no:
            print("Segmento com seq_no errado")
            return
        
        # Verifica se o segmento recebido possui a flag FIN (pode vir com outra flag junto)
        # Caso afirmativo, retorna uma confirmação para fechamento da conexão
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            print("Solicitação de fechamento de conexão")

            self.ack_no += 1
            self.callback(self, b'')

            header = make_header(dst_port, src_port, ack_no, self.ack_no, FLAGS_ACK)
            handshake_header = fix_checksum(header, dst_addr, src_addr)
            self.servidor.rede.enviar(header, src_addr)

            del self.servidor.conexoes[self.id_conexao]
            return
        
        # Verifica se o segmento recebido possui apenas a flag ACK
        # Caso afirmativo, este é apenas uma confirmação da outra ponta
        if (flags & FLAGS_ACK) == FLAGS_ACK and len(payload) == 0:
            print("Segmento ACK recebido, não é necessário enviar uma resposta.")
            return

        
        # else:       
        self.callback(self, payload)    # Notifica o recebimento do dado
        self.ack_no += len(payload)     # Atualiza o nro de reconhecimento

        header = make_header(dst_port, src_port, self.prox_seq_no, self.ack_no, FLAGS_ACK)
        handshake_header = fix_checksum(header, dst_addr, src_addr)

        self.servidor.rede.enviar(handshake_header, src_addr)


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

        self.buffer += dados
        (src_addr, src_port, dst_addr, dst_port) = self.id_conexao

        while len(self.buffer) > 0:
            # Carrega o payload e atualiza o buffer da conexão
            # *MSS é o tamanho do payload de um segmento TCP (em bytes)
            payload = self.buffer[:MSS]
            self.buffer = self.buffer[MSS:]
            
            header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            handshake_header = fix_checksum(header + payload, dst_addr, src_addr)

            self.servidor.rede.enviar(handshake_header, src_addr)
            self.seq_no += len(payload)



    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        (src_addr, src_port, dst_addr, dst_port) = self.id_conexao

        header = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_FIN)
        handshake_header = fix_checksum(header, dst_addr, src_addr)
        self.servidor.rede.enviar(handshake_header, src_addr)
