idf_component_register(SRCS "main.cpp"
                    INCLUDE_DIRS "."
                    EMBED_TXTFILES "certs/servercert.pem"
                                   "certs/prvtkey.pem")
                    #REQUIRES libdoipserver)
