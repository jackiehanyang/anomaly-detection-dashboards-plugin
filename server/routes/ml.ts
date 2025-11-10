/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

import { Router } from '../router';
import { getErrorMessage } from './utils/adHelpers';
import {
  RequestHandlerContext,
  OpenSearchDashboardsRequest,
  OpenSearchDashboardsResponseFactory,
  IOpenSearchDashboardsResponse,
} from '../../../../src/core/server';
import { getClientBasedOnDataSource } from '../utils/helpers';
import { OasisServiceSetup } from '../../../NeoDashboardsPlugin/server/oasis/service';


export function registerMLRoutes(
  apiRouter: Router,
  mlService: MLService
) {
  apiRouter.post('/agents/{agentId}/execute', mlService.executeAgent);
  apiRouter.post('/agents/{agentId}/execute/{dataSourceId}', mlService.executeAgent);
}

export default class MLService {
  private client: any;
  dataSourceEnabled: boolean;
  private oasisService?: OasisServiceSetup;

  constructor(client: any, dataSourceEnabled: boolean) {
    this.client = client;
    this.dataSourceEnabled = dataSourceEnabled;
  }

  setOasisService(oasisService: OasisServiceSetup) {
    this.oasisService = oasisService;
  }

  executeAgent = async (
    context: RequestHandlerContext,
    request: OpenSearchDashboardsRequest,
    opensearchDashboardsResponse: OpenSearchDashboardsResponseFactory
  ): Promise<IOpenSearchDashboardsResponse<any>> => {
    
    try {
      const { agentId, dataSourceId = '' } = request.params as { agentId: string, dataSourceId?: string };
      const { indices } = request.body as { indices: string[] };

      // Get capabilities from request
      const capabilities = await context.core.capabilities.resolveCapabilities(request);
      const insightsEnabled = capabilities?.ad?.insightsEnabled === true;

      // Use Oasis client if insights enabled and oasisService available
      if (insightsEnabled && this.oasisService?.getOasisConfig().enabled) {
        const oasisClient = this.oasisService.getScopedClient(request, context);
        const oasisResp = await oasisClient.request(
          {
            method: 'POST',
            path: `/_plugins/_ml/agents/${agentId}/_execute?async=true`,
            body: JSON.stringify({
              parameters: {
                input: indices
              }
            }),
            datasourceId: dataSourceId,
            stream: false,
          },
          request,
          context
        );
        
        return opensearchDashboardsResponse.ok({
          body: {
            ok: true,
            response: typeof oasisResp.body === 'string' 
              ? JSON.parse(oasisResp.body) 
              : oasisResp.body,
          },
        });
      }

      const callWithRequest = getClientBasedOnDataSource(
        context,
        this.dataSourceEnabled,
        request,
        dataSourceId,
        this.client
      );

      const requestBody = {
        parameters: {
          input: indices
        }
      };
      
      const response = await callWithRequest('ml.executeAgent', {
        agentId: agentId,
        async: true,
        body: requestBody
      });

      return opensearchDashboardsResponse.ok({
        body: {
          ok: true,
          response: response,
        },
      });
    } catch (err) {
    console.log('ML - execute agent failed', err);
    const errorDetails = err?.body?.error?.details || err?.body?.error?.reason;
      return opensearchDashboardsResponse.ok({
        body: {
          ok: false,
          error: errorDetails,
        },
      });
    }
  };
}
