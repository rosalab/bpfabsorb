// tc_ingress_clsact_filter.h
#ifndef TC_INGRESS_CLSACT_FILTER_H
#define TC_INGRESS_CLSACT_FILTER_H

#include <linux/skbuff.h>  // Needed for struct sk_buff

// Function prototype for the function to be exported
int tc_ingress_clsact_filter(struct sk_buff *skb);

#endif // TC_INGRESS_CLSACT_FILTER_H
