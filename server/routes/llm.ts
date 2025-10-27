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

import {
  RequestHandlerContext,
  OpenSearchDashboardsRequest,
  OpenSearchDashboardsResponseFactory,
  IOpenSearchDashboardsResponse,
} from '../../../../src/core/server';
import { Router } from '../router';
import { AnomalyDetectionOpenSearchDashboardsPluginConfigType } from '../index';

export function registerLLMRoutes(apiRouter: Router, config?: AnomalyDetectionOpenSearchDashboardsPluginConfigType) {
  console.log('Registering LLM routes with config:', JSON.stringify(config, null, 2));
  
  // Endpoint for OpenAI ChatGPT analysis
  apiRouter.post('/llm/analyze', async (
    context: RequestHandlerContext,
    request: OpenSearchDashboardsRequest,
    opensearchDashboardsResponse: OpenSearchDashboardsResponseFactory
  ): Promise<IOpenSearchDashboardsResponse<any>> => {
    try {
      console.log('LLM analyze endpoint called');
      console.log('Request body:', request.body);
      
      const { prompt, logs, anomalyContext } = request.body as {
        prompt: string;
        logs: any[];
        anomalyContext: any;
      };

      console.log('Config check - LLM enabled:', config?.llm?.enabled);
      
      // Check if LLM is enabled - for now, let's skip this check to test the API
      // if (!config?.llm?.enabled) {
      //   return opensearchDashboardsResponse.badRequest({
      //     body: {
      //       error: 'LLM analysis is not enabled. Please enable it in the configuration.',
      //     },
      //   });
      // }

        // Get OpenAI API key from config or environment variables
        const openaiApiKey = config?.llm?.openai?.apiKey || process.env.OPENAI_API_KEY;
        console.log('API key check - from config:', config?.llm?.openai?.apiKey ? 'Present' : 'Not set');
        console.log('API key check - from env:', process.env.OPENAI_API_KEY ? 'Present' : 'Not set');
        console.log('Final API key:', openaiApiKey ? 'Present' : 'Not found');
        
        if (!openaiApiKey) {
          console.log('No API key found, returning error');
          return opensearchDashboardsResponse.badRequest({
            body: 'OpenAI API key not configured. Please set it in config or OPENAI_API_KEY environment variable.',
          });
        }

        const openaiConfig = {
          apiKey: openaiApiKey,
          model: config?.llm?.openai?.model || 'gpt-3.5-turbo', // Use cheaper model by default
          maxTokens: config?.llm?.openai?.maxTokens || 500, // Reduce tokens to save costs
          temperature: config?.llm?.openai?.temperature || 0.3,
        };

        // Call OpenAI ChatGPT API
        const analysis = await callOpenAI(prompt, openaiConfig);

        return opensearchDashboardsResponse.ok({
          body: {
            analysis,
            metadata: {
              logCount: logs.length,
              anomalyTime: anomalyContext.anomalyTime,
              processedAt: new Date().toISOString(),
            },
          },
        });
      } catch (error: any) {
        console.error('Error in LLM analysis:', error);
        return opensearchDashboardsResponse.customError({
          statusCode: 500,
          body: {
            error: 'Failed to analyze logs with LLM',
            details: error.message,
          },
        });
      }
    });
}

// Function to call OpenAI ChatGPT API
async function callOpenAI(prompt: string, config: { apiKey: string; model: string; maxTokens: number; temperature: number }): Promise<string> {
  try {
    // Use Node.js https module instead of fetch for better compatibility
    const https = require('https');
    const requestData = JSON.stringify({
      model: config.model,
      messages: [
        {
          role: 'system',
          content: 'You are an expert system administrator and log analyst specializing in incident response and root cause analysis. Provide clear, actionable insights based on log data.'
        },
        {
          role: 'user',
          content: prompt
        }
      ],
      max_tokens: config.maxTokens,
      temperature: config.temperature,
    });

    return new Promise((resolve, reject) => {
      const options = {
        hostname: 'api.openai.com',
        port: 443,
        path: '/v1/chat/completions',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${config.apiKey}`,
          'Content-Length': Buffer.byteLength(requestData)
        }
      };

      const req = https.request(options, (res: any) => {
        let data = '';

        res.on('data', (chunk: any) => {
          data += chunk;
        });

        res.on('end', () => {
          try {
            if (res.statusCode !== 200) {
              const errorData = JSON.parse(data);
              reject(new Error(`OpenAI API error: ${res.statusCode} - ${errorData.error?.message || 'Unknown error'}`));
              return;
            }

            const responseData = JSON.parse(data);
            
            if (!responseData.choices || responseData.choices.length === 0) {
              reject(new Error('No response from OpenAI API'));
              return;
            }

            resolve(responseData.choices[0].message.content.trim());
          } catch (parseError: any) {
            reject(new Error(`Failed to parse OpenAI response: ${parseError.message}`));
          }
        });
      });

      req.on('error', (error: any) => {
        reject(new Error(`OpenAI API request failed: ${error.message}`));
      });

      req.write(requestData);
      req.end();
    });
  } catch (error: any) {
    console.error('OpenAI API call failed:', error);
    throw new Error(`Failed to get response from ChatGPT: ${error.message}`);
  }
}
