import logging
import sys
from pathlib import Path

def setup_logging(log_path="/tmp/debug.log", verbose:bool = False):
    logger = logging.getLogger("R00tKeep3r")
    logger.setLevel(logging.DEBUG) # all message including debug , info , warning , error , critical will be processed

    # to avoid duplicate handlers
    if logger.hasHandlers(): 
        logger.handlers.clear()
    
    # File handler >> elly by-save fl file
    file_handler = logging.FileHandler(log_path) # opens or creates log file 
    file_formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(module)s - %(message)s", # by format el log ykon nfs el haga l kollo >> time level name (ex debug) module message
        datefmt="%H:%M:%S"                             
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Console handler  >>  elly byzhr fl terminal lel user
    console_handler = logging.StreamHandler(sys.stdout)
    console_level = logging.DEBUG if verbose else logging.INFO
    console_formatter = logging.Formatter("%(message)s") # only show the message , no timestamp wl module w kda
    console_handler.setLevel(console_level) # only messages in info level and higher will be printed on screen (no debug)
    console_handler.setFormatter(console_formatter) 
    
    logger.addHandler(console_handler)
    
    return logger

# Singleton instance
logger = setup_logging(verbose=False)