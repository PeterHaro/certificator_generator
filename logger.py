#!/usr/bin/env python2
import sys
import time


class Logger(object):
    EMERGENCY = 1 << 0
    ALERT = 1 << 1
    CRITICAL = 1 << 2
    ERROR = 1 << 3
    WARN = 1 << 4
    NOTICE = 1 << 5
    INFO = 1 << 6
    DEBUG = 1 << 7

    IEMERGENCY = EMERGENCY | EMERGENCY - 1
    IALERT = ALERT | ALERT - 1
    ICRITICAL = CRITICAL | CRITICAL - 1
    IERROR = ERROR | ERROR - 1
    IWARN = WARN | WARN - 1
    INOTICE = NOTICE | NOTICE - 1
    IINFO = INFO | INFO - 1
    IDEBUG = DEBUG | DEBUG - 1

    ALL = -1
    NON = 0
    DEFAULT = IWARN

    def __init__(self, writer=None, mask=DEFAULT, identifier=""):
        self.writers = {}
        self.add_writer(writer, mask)
        self.identifier = identifier

    def add_writer(self, writer, mask=DEFAULT):
        if writer is not None:
            self.set_mask(writer, mask)
        else:
            self.error("Tried to add already added writer %s" % (str(writer)), "LOGGER")

    def get_mask(self, writer):
        return self.writers[writer]

    def set_mask(self, writer, mask):
        self.writers[writer] = mask

    def get_identifier(self, identifier):
        return self.identifier

    def set_identifier(self, identifier):
        self.identifier = identifier

    def log(self, tag, message, prefix=""):
        for writer, mask in self.writers.iteritems():
            if (mask & tag) == 0:
                continue

            timestamp = time.strftime("%Y-%m-%d %H:%M:%S %z")
            writer.write("\t".join([timestamp, self.identifier, "0x%08x" % (tag), prefix, message.strip()]) + "\n")
            writer.flush()

    def panic(self, message, prefix=""):
        self.emergency(message, prefix)
        sys.exit(1)

    def throw(self, exception_class, message, prefix=""):
        self.error(message, prefix)
        raise exception_class(message)

    def emergency(self, message, prefix=""):
        self.log(self.EMERGENCY, message, prefix)

    def alert(self, message, prefix=""):
        self.log(self.ALERT, message, prefix)

    def critical(self, message, prefix=""):
        self.log(self.CRITICAL, message, prefix)

    def error(self, message, prefix=""):
        self.log(self.ERROR, message, prefix)

    def warn(self, message, prefix=""):
        self.log(self.WARN, message, prefix)

    def notice(self, message, prefix=""):
        self.log(self.NOTICE, message, prefix)

    def info(self, message, prefix=""):
        self.log(self.INFO, message, prefix)

    def debug(self, message, prefix=""):
        self.log(self.DEBUG, message, prefix)


if __name__ == "__main__":
    logger = Logger(sys.stderr)
    logger.add_writer(sys.stdout, Logger.ALL)
    logger.log(0xdeadbeef, "A funny message")
    logger.log(0xc0ffee, "Another message", "PREFIX")

    logger.emergency("An emergency")
    logger.alert("An alert")
    logger.critical("Something critical")
    logger.error("An error", "AnOtHeR")
    logger.warn("A warning")
    logger.notice("A notice")
    logger.info("Some info")
    logger.debug("Some debug info")
