import logging

logger = None


def Logger(filename=None):
    global logger
    if not logger:
        logger = logging.getLogger()
        if filename is not None:
            print 'Logfile : %s' % filename
            create_file_handler(logger, filename)
        handler = logging.StreamHandler()
        handler.setFormatter(
        logging.Formatter('%(filename)s [LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s] %(message)s'))
        handler.setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        logger.name = filename
    else:
        if filename is not None:
            print 'NEW Logfile : %s' % filename
            logger.name = filename
            logger.removeHandler(get_file_handler(logger.handlers))
            create_file_handler(logger, filename)
    return logger

def log(message):
    logger = Logger()
    logger.info(message)
    print message

def get_file_handler(handlers):
    for hand in handlers:
        if hand.__class__ == logging.FileHandler:
            return hand


def create_file_handler(logger, file):
    filehandler = logging.FileHandler(file, 'w')
    filehandler.setFormatter(
    logging.Formatter('%(filename)-15s [LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s] %(message)s'))
    filehandler.setLevel(logging.DEBUG)
    logger.addHandler(filehandler)

