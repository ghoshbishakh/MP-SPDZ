/*
 * MascotEcPrep.h
 *
 */

#ifndef PROTOCOLS_MASCOTECPREP_H_
#define PROTOCOLS_MASCOTECPREP_H_

#include "ReplicatedPrep.h"
#include "OT/MascotParams.h"
#include "Protocols/Share.h"
#include "Protocols/MascotPrep.h"
#include "Protocols/ReplicatedPrep.h"


// T is Share<P256Element>, V is Share<gfp>
template<class T, class V>
class MascotEcPrep :public BufferPrep<T>
{

typedef MascotFieldPrep<V> scalar_preprocessing;

public:
    MascotEcPrep<T, V>(DataPositions& usage);

};


#endif /* PROTOCOLS_MASCOTECPREP_H_ */
