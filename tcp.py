import asyncio
from grader.tcputils import *
import random


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
        self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        #self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida

        src_addr, src_port, dst_addr, dst_port = id_conexao

        # criacao de header invertendo origem e destino e passando seq_no_y e ack de recebimento de seq_no
        header = make_header(dst_port, src_port, seq_no, seq_no+1, FLAGS_ACK | FLAGS_SYN)

        # arruma checksum antes do envio
        header = fix_checksum(header, dst_addr, src_addr)

        # envio do segmento para scr_addr (endereco de onde conexao veio)
        self.servidor.rede.enviar(header, src_addr)

        self.seq_no_to_send = seq_no + 1 # proximo seq_no a enviar (seq_no acabou de ser enviado)
        self.seq_no_to_receive = ack_no # prox seq_no a receber

    def _exemplo_timer(self):
        # Esta função é só um exemplo e pode ser removida
        print('Este é um exemplo de como fazer um timer')

    # funcao que recebe pacotes da conexao ja estabelecida
    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.
        # print('recebido payload: %r' % payload)

        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        # se recebe segmento setado como fin de seq_no = x, responde ack = x+1 para indicar recebimento
        if (flags & FLAGS_FIN | FLAGS_ACK) == FLAGS_FIN | FLAGS_ACK:
            self.seq_no_to_receive += 1

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
    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        # TODO: implemente aqui o envio de dados.
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        # que você construir para a camada de rede.
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        while len(dados) > 0:

            # limita payload a MSS (Maximum Segment Size) para evitar flow problems
            payload = dados[:MSS]

            # eventuais dados que sobraram
            dados = dados[MSS:]

            segmento = make_header(dst_port, src_port, self.seq_no_to_send, self.seq_no_to_receive, FLAGS_ACK)
            segmento = fix_checksum(segmento+payload, dst_addr, src_addr)
            self.servidor.rede.enviar(segmento, src_addr)

            # atualiza proximo seq_no a enviar
            self.seq_no_to_send += len(payload)


    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        header = make_header(dst_port, src_port, self.seq_no_to_send, self.seq_no_to_receive, FLAGS_FIN | FLAGS_ACK)
        header = fix_checksum(header, dst_addr, src_addr)
        self.servidor.rede.enviar(header, src_addr)
