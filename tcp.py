import asyncio
from grader.tcputils import *
import random
import time

INITIAL_TIMEOUT_INTERVAL = 1
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

    # chamada quando um segmento chega do lado do servidor (header|data)
    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        # flag de SYN indica nova conexao a ser realizada
        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # TODO: talvez você precise passar mais coisas para o construtor de conexão

            # criacao de nova conexao - seq_no + 1 eh o ack para confirmar que recebeu pacote seq_no
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no, seq_no+1)
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.

            if self.callback:
                self.callback(conexao)

        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida

            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)

            if (flags & FLAGS_FIN) == FLAGS_FIN:
                dados = b''
                self.conexoes[id_conexao].callback(self, dados)
                self.conexoes[id_conexao].fechar()
                
                self.conexoes.pop(id_conexao)

        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        # [ (unacked_segment_no, payload, sending_time, retransmitted_packet = true | false), ... ]
        self.unacked_segments = []
        src_addr, src_port, dst_addr, dst_port = id_conexao
        self.timeout_interval = 1 # definicao inicial apenas ate definir estimar timeout_interval
        self.dev_rtt = None
        self.estimated_rtt = None
        self.alpha = 0.125
        self.beta = 0.25
        self.dados = None
        self.cwnd = 1

        # criacao de header invertendo origem e destino e passando seq_no_y e ack de recebimento de seq_no
        header = make_header(dst_port, src_port, seq_no, seq_no+1, FLAGS_ACK | FLAGS_SYN)

        # arruma checksum antes do envio
        header = fix_checksum(header, dst_addr, src_addr)

        # envio do segmento para scr_addr (endereco de onde conexao veio)
        self.servidor.rede.enviar(header, src_addr)

        self.seq_no_to_send = seq_no + 1 # proximo seq_no a enviar (seq_no acabou de ser enviado)
        self.seq_no_to_receive = ack_no # prox seq_no a receber

    def handle_timer(self):
        self.cwnd = self.cwnd // 2
        # Esta função é só um exemplo e pode ser removida
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        # informacoes do segmento perdido para reenviar
        last_unacked_segment_seq_no = self.unacked_segments[0][0] 
        last_unacked_segment_data = self.unacked_segments[0][1]
        initial_time = self.unacked_segments[0][2]

        new_sending_time = time.time()
        self.unacked_segments[0][2] = new_sending_time
        self.unacked_segments[0][3] = True
        
        # reenvio do segmento
        segmento = make_header(dst_port, src_port, last_unacked_segment_seq_no, self.seq_no_to_receive, FLAGS_ACK)
        segmento = fix_checksum(segmento+last_unacked_segment_data, dst_addr, src_addr)
        self.servidor.rede.enviar(segmento, src_addr)

        # reinicia timer para segmento reenviado
        self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self.handle_timer)


    def update_estimated_rtt(self, sample_rtt):
        if (self.timeout_interval == 1):
            self.estimated_rtt = sample_rtt
        else:
            self.estimated_rtt = (1-self.alpha) * self.estimated_rtt + self.alpha * sample_rtt


    def update_dev_rtt(self, sample_rtt):
        if (self.timeout_interval == 1):
            self.dev_rtt = sample_rtt/2
        else:
            self.dev_rtt = (1-self.beta) * self.dev_rtt + self.beta * abs(sample_rtt - self.estimated_rtt)

    def update_timeout_interval(self, sample_rtt):
        self.update_estimated_rtt(sample_rtt)
        self.update_dev_rtt(sample_rtt)

        self.timeout_interval = self.estimated_rtt + 4*self.dev_rtt

    # funcao que recebe pacotes da conexao ja estabelecida
    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.

        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        # se recebe segmento setado como fin de seq_no = x, responde ack = x+1 para indicar recebimento
        if (flags & FLAGS_FIN | FLAGS_ACK) == FLAGS_FIN | FLAGS_ACK:
            self.seq_no_to_receive += 1

        # se chegou algum ack
        if (flags & FLAGS_ACK) ==  FLAGS_ACK and len(self.unacked_segments) > 0:

            # achar maneira de incrementar cwnd conforme recebe-se um ack de uma janela inteira 

            receive_time = time.time()

            # self.seq_no_to_receive = sendBase
            if (ack_no > self.seq_no_to_send):
                self.seq_no_to_send = ack_no

            # # marca como acked seg# receive_time = mentos unacked considerando ack cumulativo
            for unacked_segment in self.unacked_segments:
                if unacked_segment[0] + len(unacked_segment[1]) == ack_no and not unacked_segment[3]:
                    sample_rtt = receive_time - unacked_segment[2]
                    self.update_timeout_interval(sample_rtt)
                    break

            self.unacked_segments = [unacked_segment for unacked_segment in self.unacked_segments if unacked_segment[0] >= ack_no]
            if len(self.unacked_segments) > 0:
                self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self.handle_timer)
            else:
                self.timer.cancel()
                self.cwnd += 1

            if (len(self.dados) > 0):
                self.enviar(self.dados, reenvio=True)


        # garante que pacote que chegou eh o esperado e na ordem
        # len(payload) > 0 garante que recebimento de pacote ack nao gera resposta
        if (seq_no == self.seq_no_to_receive and len(payload) > 0):
            
            # incrementa proximo seq_no esperado 
            self.seq_no_to_receive += len(payload)
            self.callback(self, payload)

            # envia segmento
            segmento = make_header(dst_port, src_port, self.seq_no_to_send, self.seq_no_to_receive, FLAGS_ACK)
            segmento = fix_checksum(segmento, dst_addr, src_addr)

            self.servidor.rede.enviar(segmento, src_addr)

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    # Nesta primeira parte, vamos nos preocupar somente com o evento "dados recebidos da camada de aplicação acima". Ou seja, 
    # mantenha uma contagem correta do número de sequência a ser inserido no segmento e construa o segmento corretamente, 
    # enviando-o em seguida para a camada de rede.
    # Por simplicidade, mantenha a flag de ACK sempre ligada nos segmentos que você enviar, incluindo corretamente o acknowledgement 
    # number correspondente ao próximo byte que você espera receber. Note que essa contagem refere-se ao funcionamento da nossa ponta
    # como receptor, e não como transmissor, mas aqui misturamos os papéis.

    # funcao para enviar dados da aplicacao para rede
    def enviar(self, dados, reenvio=False):
        """
        Usado pela camada de aplicação para enviar dados
        """
        # TODO: implemente aqui o envio de dados.
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        # que você construir para a camada de rede.
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        if (self.dados is None):
            self.dados = dados
        elif not reenvio:
            self.dados += dados
        while len(self.dados) > 0 and len(self.unacked_segments) < self.cwnd:

            # limita payload a MSS (Maximum Segment Size) para evitar flow problems
            payload = self.dados[:MSS]

            # eventuais dados que sobraram
            self.dados = self.dados[MSS:]

            segmento = make_header(dst_port, src_port, self.seq_no_to_send, self.seq_no_to_receive, FLAGS_ACK)
            segmento = fix_checksum(segmento+payload, dst_addr, src_addr)
            sending_time = time.time()
            self.servidor.rede.enviar(segmento, src_addr)

            # atualiza proximo seq_no a enviar
            self.unacked_segments.append([self.seq_no_to_send, payload, sending_time, False])
            self.seq_no_to_send += len(payload)
            if (len(self.unacked_segments) == 1):
                self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self.handle_timer)

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        header = make_header(dst_port, src_port, self.seq_no_to_send, self.seq_no_to_receive, FLAGS_FIN | FLAGS_ACK)
        header = fix_checksum(header, dst_addr, src_addr)
        self.servidor.rede.enviar(header, src_addr)
