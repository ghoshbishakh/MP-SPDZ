/*
 * fake-spdz-ecdsa-party.cpp
 *
 */

#include "Networking/Server.h"
#include "Networking/CryptoPlayer.h"
#include "Math/gfp.h"
#include "ECDSA/P256Element.h"
#include "Protocols/SemiShare.h"
#include "Processor/BaseMachine.h"

#include "ECDSA/preprocessing.hpp"
#include "ECDSA/sign.hpp"
#include "Protocols/Beaver.hpp"
#include "Protocols/fake-stuff.hpp"
#include "Protocols/MascotPrep.hpp"
#include "Processor/Processor.hpp"
#include "Processor/Data_Files.hpp"
#include "Processor/Input.hpp"
#include "GC/TinyPrep.hpp"
#include "GC/VectorProtocol.hpp"
#include "GC/CcdPrep.hpp"
#include "Protocols/ProtocolSet.h"

#include <assert.h>

template<template<class U> class T>
void run(int argc, const char** argv)
{
    ez::ezOptionParser opt;
    EcdsaOptions opts(opt, argc, argv);
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Use SimpleOT instead of OT extension", // Help description.
            "-S", // Flag token.
            "--simple-ot" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Don't check correlation in OT extension (only relevant with MASCOT)", // Help description.
            "-U", // Flag token.
            "--unchecked-correlation" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Fewer rounds for authentication (only relevant with MASCOT)", // Help description.
            "-A", // Flag token.
            "--auth-fewer-rounds" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Use Fiat-Shamir for amplification (only relevant with MASCOT)", // Help description.
            "-H", // Flag token.
            "--fiat-shamir" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "Skip sacrifice (only relevant with MASCOT)", // Help description.
            "-E", // Flag token.
            "--embrace-life" // Flag token.
    );
    opt.add(
            "", // Default.
            0, // Required?
            0, // Number of args expected.
            0, // Delimiter if expecting multiple args.
            "No MACs (only relevant with MASCOT; implies skipping MAC checks)", // Help description.
            "-M", // Flag token.
            "--no-macs" // Flag token.
    );

    // set up networking
    Names N(opt, argc, argv, 2);
    int n_tuples = 1000;
    if (not opt.lastArgs.empty())
        n_tuples = atoi(opt.lastArgs[0]->c_str());
    PlainPlayer P(N, "ecdsa");

    // Configure the curve and the field
    P256Element::init();
    P256Element::Scalar::next::init_field(P256Element::Scalar::pr(), false);
    int prime_length = P256Element::Scalar::length();

    // Do we need these?
    BaseMachine machine;
    machine.ot_setups.push_back({P, true});

    P256Element::Scalar keyp;
    SeededPRNG G;
    keyp.randomize(G);

    typedef T<P256Element::Scalar> pShare;

    // DataPositions usage;

    // Protocol Set
    ProtocolSetup<pShare> protocolSetup(P, prime_length);
    ProtocolSet<pShare> protocolSet(P, protocolSetup);

    OnlineOptions::singleton.batch_size = 1;


    // typename pShare::Direct_MC MCp(keyp);
    // ArithmeticProcessor _({}, 0);
    // typename pShare::TriplePrep sk_prep(0, usage);
    // SubProcessor<pShare> sk_proc(_, MCp, sk_prep, P);
    pShare sk, __;
    // synchronize
    Bundle<octetStream> bundle(P);
    P.unchecked_broadcast(bundle);
    Timer timer;
    timer.start();
    auto stats = P.total_comm();
    // sk_prep.get_two(DATA_INVERSE, sk, __);
    protocolSet.preprocessing.get_two(DATA_INVERSE, sk, __);
    cout << "Secret key generation took " << timer.elapsed() * 1e3 << " ms" << endl;
    (P.total_comm() - stats).print(true);

    OnlineOptions::singleton.batch_size = (1 + pShare::Protocol::uses_triples) * n_tuples;
    // typename pShare::TriplePrep prep(0, usage);
    protocolSet.preprocessing.params.correlation_check &= not opt.isSet("-U");
    protocolSet.preprocessing.params.fewer_rounds = opt.isSet("-A");
    protocolSet.preprocessing.params.fiat_shamir = opt.isSet("-H");
    protocolSet.preprocessing.params.check = not opt.isSet("-E");
    protocolSet.preprocessing.params.generateMACs = not opt.isSet("-M");
    opts.check_beaver_open &= protocolSet.preprocessing.params.generateMACs;
    opts.check_open &= protocolSet.preprocessing.params.generateMACs;
    // SubProcessor<pShare> proc(_, MCp, prep, P);
    // typename pShare::prep_type::Direct_MC MCpp(keyp);
    // protocolSet.preprocessing.triple_generator->MC = &MCpp;

    // bool prep_mul = not opt.isSet("-D");
    protocolSet.preprocessing.params.use_extension = not opt.isSet("-S");
    vector<EcTuple<T>> tuples;
    cout << "---------- Start preprocessing ------------" << endl;
    preprocessing(protocolSet, tuples, n_tuples, sk, opts);
    // //check(tuples, sk, keyp, P);
    // sign_benchmark(tuples, sk, MCp, P, opts, prep_mul ? 0 : &proc);
}
