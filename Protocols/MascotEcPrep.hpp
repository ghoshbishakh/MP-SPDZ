/*
 * MascotEcPrep.cpp
 *
 */

#ifndef PROTOCOLS_MASCOTECPREP_HPP_
#define PROTOCOLS_MASCOTECPREP_HPP_

#include "MascotEcPrep.h"



template<class T, class V>
MascotEcPrep<T, V>::MascotEcPrep(DataPositions& usage):
BufferPrep<T>(usage)
{
scalar_preprocessing(0, usage);
}



#endif
