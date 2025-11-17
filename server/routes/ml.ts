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
  constructor(client: any, dataSourceEnabled: boolean) {
    this.client = client;
    this.dataSourceEnabled = dataSourceEnabled;
  }

  executeAgent = async (
    context: RequestHandlerContext,
    request: OpenSearchDashboardsRequest,
    opensearchDashboardsResponse: OpenSearchDashboardsResponseFactory
  ): Promise<IOpenSearchDashboardsResponse<any>> => {
    try {
      const { agentId, dataSourceId = '' } = request.params as { agentId: string, dataSourceId?: string };
      const { indices } = request.body as { indices: string[] };

      // Use Oasis client if available
      try {
        const oasisResp = await context.oasis?.client.request(
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
        if (oasisResp) {
          if (oasisResp.status < 400) {
            return opensearchDashboardsResponse.ok({
              body: {
                ok: true,
                response: oasisResp?.body,
              },
            });
          } else {
            return opensearchDashboardsResponse.ok({
              body: {
                ok: false,
                error: oasisResp?.body || oasisResp?.statusText,
              },
            });
          }
        }
      } catch (oasisErr) {
        console.error('ML - Oasis client request failed, falling back to regular client', oasisErr);
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
      console.error('ML - execute agent failed', err);
      const errorDetails = err?.body?.error?.details || err?.body?.error?.reason || err?.message || 'Fail to execute create detector agent';
      return opensearchDashboardsResponse.ok({
        body: {
          ok: false,
          error: errorDetails,
        },
      });
    }
  };
}
