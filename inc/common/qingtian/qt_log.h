#ifndef QT_LOG_H
#define QT_LOG_H

#include <stdio.h>

#ifdef DEBUG
    #define QT_INFO(fmt, args...) printf(fmt, ##args)
    #define QT_DEBUG(fmt, args...) printf(fmt, ##args)
    #define QT_ERR(fmt, args...) printf(fmt, ##args)
#else
    #define QT_INFO(fmt, args...)
    #define QT_DEBUG(fmt, args...)
    #define QT_ERR(fmt, args...) printf(fmt, ##args)
#endif

#endif
