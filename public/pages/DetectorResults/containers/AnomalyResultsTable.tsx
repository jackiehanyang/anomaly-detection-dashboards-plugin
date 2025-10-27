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
  EuiBasicTable as EuiBasicTableComponent,
  EuiEmptyPrompt,
  EuiText,
  EuiButton,
  EuiLoadingSpinner,
  EuiPopover,
  EuiPopoverTitle,
  EuiPopoverFooter,
  EuiButtonEmpty,
  EuiIcon,
  EuiToolTip,
} from '@elastic/eui';
import { get } from 'lodash';
import React, { useEffect, useState } from 'react';
import { first } from 'rxjs/operators';
import { SORT_DIRECTION } from '../../../../server/utils/constants';
import ContentPanel from '../../../components/ContentPanel/ContentPanel';
import {
  entityValueColumn,
  staticColumn,
  ENTITY_VALUE_FIELD,
} from '../utils/tableUtils';
import { DetectorResultsQueryParams } from 'server/models/types';
import { AnomalyData, Anomalies } from '../../../models/interfaces';
import { getTitleWithCount } from '../../../utils/utils';
import { convertToCategoryFieldAndEntityString } from '../../utils/anomalyResultUtils';
import { HeatmapCell } from '../../AnomalyCharts/containers/AnomalyHeatmapChart';
import { getSavedObjectsClient, getNotifications, getDataSourceEnabled } from '../../../services';
import { CoreStart } from '../../../../../../src/core/public';
import { CoreServicesContext } from '../../../components/CoreServices/CoreServices';
import { useLocation } from 'react-router-dom';
import { getDataSourceFromURL } from '../../../../public/pages/utils/helpers';
import { setStateToOsdUrl } from '../../../../../../src/plugins/opensearch_dashboards_utils/public';
import { opensearchFilters, IIndexPattern } from '../../../../../../src/plugins/data/public';
import { AnomalyInsightGenerator, ComprehensiveInsight, formatInsightsForDisplay } from '../utils/insightGenerator';
import { LogEntry } from '../utils/statisticalAnalysis';

//@ts-ignore
const EuiBasicTable = EuiBasicTableComponent as any;

interface AnomalyResultsTableProps {
  anomalies: AnomalyData[];
  isHCDetector?: boolean;
  isHistorical?: boolean;
  selectedHeatmapCell?: HeatmapCell | undefined;
  detectorIndices: string[];
  detectorTimeField: string;
  anomalyAndFeatureResults?: Anomalies[];
  detector?: any;
}

interface ListState {
  page: number;
  queryParams: DetectorResultsQueryParams;
}
const MAX_ANOMALIES = 10000;

export function AnomalyResultsTable(props: AnomalyResultsTableProps) {
  const [state, setState] = useState<ListState>({
    page: 0,
    queryParams: {
      from: 0,
      size: 10,
      sortDirection: SORT_DIRECTION.DESC,
      sortField: 'startTime',
    },
  });
  const [targetAnomalies, setTargetAnomalies] = useState<any[]>([] as any[]);
  
  // State for LLM analysis
  const [llmAnalysisResults, setLlmAnalysisResults] = useState<{[key: string]: string}>({});
  const [loadingLLMAnalysis, setLoadingLLMAnalysis] = useState<{[key: string]: boolean}>({});
  const [llmAnalysisErrors, setLlmAnalysisErrors] = useState<{[key: string]: string}>({});
  const [openLLMPopovers, setOpenLLMPopovers] = useState<{[key: string]: boolean}>({});
  
  // State for statistical analysis
  const [statisticalAnalysisResults, setStatisticalAnalysisResults] = useState<{[key: string]: ComprehensiveInsight[]}>({});
  const [loadingStatisticalAnalysis, setLoadingStatisticalAnalysis] = useState<{[key: string]: boolean}>({});
  const [statisticalAnalysisErrors, setStatisticalAnalysisErrors] = useState<{[key: string]: string}>({});
  const [openStatisticalPopovers, setOpenStatisticalPopovers] = useState<{[key: string]: boolean}>({});
  
  // Initialize insight generator
  const insightGenerator = React.useMemo(() => new AnomalyInsightGenerator(), []);
  
  const core = React.useContext(CoreServicesContext) as CoreStart;

  const location = useLocation();
  const MDSQueryParams = getDataSourceFromURL(location);
  const dataSourceId = MDSQueryParams.dataSourceId;
  
  // Only return anomalies if they exist. If high-cardinality: only show when a heatmap cell is selected
  const totalAnomalies =
    props.anomalies &&
    ((props.isHCDetector && props.selectedHeatmapCell) || !props.isHCDetector)
      ? props.anomalies.filter((anomaly) => anomaly.anomalyGrade > 0)
      : [];



  // Function to find feature output values for a specific anomaly
  const getFeatureOutputValues = (anomalyTime: number, anomalyEntity?: any) => {
    const featureValues: { [featureName: string]: number } = {};
    
    if (!props.anomalyAndFeatureResults || !props.detector?.featureAttributes) {
      return featureValues;
    }

    // Find the feature data that matches the anomaly time and entity
    props.anomalyAndFeatureResults.forEach((timeSeries: any) => {
      if (timeSeries.featureData) {
        Object.keys(timeSeries.featureData).forEach((featureId: string) => {
          const featureDataPoints = timeSeries.featureData[featureId];
          
          // Find the feature data point that matches the anomaly time
          const matchingFeaturePoint = featureDataPoints.find((point: any) => {
            return Math.abs(point.plotTime - anomalyTime) < 30000; // 30 second tolerance
          });
          
          if (matchingFeaturePoint) {
            // Find the feature name from detector configuration
            const featureConfig = props.detector.featureAttributes.find((attr: any) => 
              attr.featureId === featureId
            );
            
            if (featureConfig) {
              // Extract the actual field name and aggregation method from the aggregation query
              let fieldName = featureConfig.featureName || featureId;
              let aggregationMethod = '';
              
              // Try to extract field name and method from aggregation query
              if (featureConfig.aggregationQuery) {
                try {
                  const aggregationKeys = Object.keys(featureConfig.aggregationQuery);
                  if (aggregationKeys.length > 0) {
                    const firstAggregation = featureConfig.aggregationQuery[aggregationKeys[0]];
                    const methodKeys = Object.keys(firstAggregation);
                    if (methodKeys.length > 0) {
                      aggregationMethod = methodKeys[0]; // e.g., 'min', 'max', 'sum', 'avg'
                      const method = firstAggregation[methodKeys[0]];
                      if (method && method.field) {
                        fieldName = method.field;
                      }
                    }
                  }
                } catch (error) {
                  console.warn('Error extracting field name from aggregation query:', error);
                }
              }
              
              // Only add feature filter for min/max aggregation methods
              if (aggregationMethod === 'min' || aggregationMethod === 'max') {
                featureValues[fieldName] = matchingFeaturePoint.data;
              }
            } else {
              // Fallback: use the feature name from the data point if available
              const fieldName = matchingFeaturePoint.name || featureId;
              featureValues[fieldName] = matchingFeaturePoint.data;
            }
          }
        });
      }
    });
    
    return featureValues;
  };

  // Function to fetch logs for statistical analysis (less restrictive)
  const fetchLogsForStatisticalAnalysis = async (startTime: number, endTime: number, item: any) => {
    try {
      // Expand the time window to get more logs for analysis
      const TEN_MINUTES_IN_MS = 10 * 60 * 1000;
      const FIVE_MINUTES_IN_MS = 5 * 60 * 1000;
      const fromTime = startTime - TEN_MINUTES_IN_MS; // 10 minutes before
      const toTime = endTime + FIVE_MINUTES_IN_MS;    // 5 minutes after

      // Build a less restrictive query for statistical analysis
      const query: any = {
        query: {
          bool: {
            must: [
              {
                range: {
                  [props.detectorTimeField]: {
                    gte: fromTime,
                    lte: toTime,
                  }
                }
              }
            ]
          }
        },
        sort: [{ [props.detectorTimeField]: { order: 'desc' } }],
        size: 500, // Increased limit for better analysis
        _source: true
      };

      const indexPattern = props.detectorIndices.join(',');
      
      // Execute the search query
      const response = await core.http.post('/api/console/proxy', {
        query: {
          path: `/${indexPattern}/_search`,
          method: 'POST'
        },
        body: JSON.stringify(query)
      });

      if (response.hits && response.hits.hits) {
        return response.hits.hits.map((hit: any) => hit._source);
      }
      
      return [];
    } catch (error) {
      console.error('Error fetching logs for statistical analysis:', error);
      return [];
    }
  };

  // Function to fetch logs for LLM analysis (with strict filtering)
  const fetchLogsForAnalysis = async (startTime: number, endTime: number, item: any) => {
    try {
      const TEN_MINUTES_IN_MS = 10 * 60 * 1000;
      const fromTime = startTime - TEN_MINUTES_IN_MS;
      const toTime = endTime + TEN_MINUTES_IN_MS;

      // Build the same query that would be used in Discover
      const query: any = {
        query: {
          bool: {
            must: [
              {
                range: {
                  [props.detectorTimeField]: {
                    gte: fromTime,
                    lte: toTime,
                  }
                }
              }
            ]
          }
        },
        sort: [{ [props.detectorTimeField]: { order: 'desc' } }],
        size: 500, // Increased limit to 500 logs for better analysis
        _source: true
      };

      // Add entity filters for HC detectors
      if (props.isHCDetector && item[ENTITY_VALUE_FIELD]) {
        const entityValues = item[ENTITY_VALUE_FIELD].split('\n').map((s: string) => s.trim()).filter(Boolean);
        entityValues.forEach((entityValue: string) => {
          const [field, value] = entityValue.split(': ').map((s: string) => s.trim());
          query.query.bool.must.push({
            match_phrase: { [field]: value }
          });
        });
      }

      // Add feature filters for min/max aggregations
      const featureValues = getFeatureOutputValues(item.plotTime || item.endTime, item.entity);
      Object.keys(featureValues).forEach((featureName: string) => {
        const featureValue = featureValues[featureName];
        query.query.bool.must.push({
          match_phrase: { [featureName]: featureValue }
        });
      });

      const indexPattern = props.detectorIndices.join(',');
      
      // Execute the search query
      const response = await core.http.post('/api/console/proxy', {
        query: {
          path: `/${indexPattern}/_search`,
          method: 'POST'
        },
        body: JSON.stringify(query)
      });

      const hits = response.hits?.hits || [];
      return hits.map((hit: any) => hit._source);
    } catch (error) {
      console.error('Error fetching logs for analysis:', error);
      throw error;
    }
  };

  // Function to fetch ALL logs for comprehensive LLM analysis (no size limit)
  const fetchAllLogsForAnalysis = async (startTime: number, endTime: number, item: any) => {
    try {
      const TEN_MINUTES_IN_MS = 10 * 60 * 1000;
      const fromTime = startTime - TEN_MINUTES_IN_MS;
      const toTime = endTime + TEN_MINUTES_IN_MS;

      console.log(`[Method 3] Fetching ALL logs from ${new Date(fromTime).toISOString()} to ${new Date(toTime).toISOString()}`);
      const fetchStartTime = Date.now();

      // Build the same query but without size limit
      const query: any = {
        query: {
          bool: {
            must: [
              {
                range: {
                  [props.detectorTimeField]: {
                    gte: fromTime,
                    lte: toTime,
                  }
                }
              }
            ]
          }
        },
        sort: [{ [props.detectorTimeField]: { order: 'asc' } }], // Chronological order for LLM
        size: 10000, // Maximum allowed by OpenSearch (effectively unlimited for most cases)
        _source: true
      };

      // Add entity filters for HC detectors
      if (props.isHCDetector && item[ENTITY_VALUE_FIELD]) {
        const entityValues = item[ENTITY_VALUE_FIELD].split('\n').map((s: string) => s.trim()).filter(Boolean);
        entityValues.forEach((entityValue: string) => {
          const [field, value] = entityValue.split(': ').map((s: string) => s.trim());
          query.query.bool.must.push({
            match_phrase: { [field]: value }
          });
        });
      }

      // Add feature filters for min/max aggregations
      const featureValues = getFeatureOutputValues(item.plotTime || item.endTime, item.entity);
      Object.keys(featureValues).forEach((featureName: string) => {
        const featureValue = featureValues[featureName];
        query.query.bool.must.push({
          match_phrase: { [featureName]: featureValue }
        });
      });

      const indexPattern = props.detectorIndices.join(',');
      
      // Execute the search query
      const response = await core.http.post('/api/console/proxy', {
        query: {
          path: `/${indexPattern}/_search`,
          method: 'POST'
        },
        body: JSON.stringify(query)
      });

      const hits = response.hits?.hits || [];
      const logs = hits.map((hit: any) => hit._source);
      
      const fetchEndTime = Date.now();
      const fetchDuration = fetchEndTime - fetchStartTime;
      
      console.log(`[Method 3] Fetched ${logs.length} logs in ${fetchDuration}ms`);
      console.log(`[Method 3] Estimated payload size: ${JSON.stringify(logs).length} characters`);
      
      return logs;
    } catch (error) {
      console.error('Error fetching ALL logs for analysis:', error);
      throw error;
    }
  };

  // Function to select balanced logs for LLM analysis
  const getBalancedLogsForAnalysis = (logs: any[], anomalyContext: any) => {
    console.log(`getBalancedLogsForAnalysis called with ${logs.length} logs`);
    const anomalyTime = anomalyContext.startTime;
    const maxLogs = 50;
    
    if (logs.length <= maxLogs) {
      console.log(`Returning all ${logs.length} logs (under limit)`);
      return logs;
    }

    // Separate logs into before, during, and after anomaly
    const beforeLogs = logs.filter(log => {
      const logTime = new Date(log['@timestamp'] || log.timestamp || log._timestamp).getTime();
      return logTime < anomalyTime;
    });
    
    const duringLogs = logs.filter(log => {
      const logTime = new Date(log['@timestamp'] || log.timestamp || log._timestamp).getTime();
      return logTime >= anomalyContext.startTime && logTime <= anomalyContext.endTime;
    });
    
    const afterLogs = logs.filter(log => {
      const logTime = new Date(log['@timestamp'] || log.timestamp || log._timestamp).getTime();
      return logTime > anomalyContext.endTime;
    });

    // Balanced selection: prioritize during, then before, then after
    const selectedLogs = [];
    
    // Take all "during" logs (highest priority)
    const duringCount = Math.min(duringLogs.length, Math.floor(maxLogs * 0.4)); // 40% for during
    selectedLogs.push(...duringLogs.slice(0, duringCount));
    
    const remaining = maxLogs - selectedLogs.length;
    
    // Take "before" logs (second priority) - most recent before anomaly
    const beforeCount = Math.min(beforeLogs.length, Math.floor(remaining * 0.6)); // 60% of remaining for before
    selectedLogs.push(...beforeLogs.slice(0, beforeCount));
    
    const stillRemaining = maxLogs - selectedLogs.length;
    
    // Fill remainder with "after" logs
    if (stillRemaining > 0) {
      selectedLogs.push(...afterLogs.slice(0, stillRemaining));
    }
    
    // Sort by timestamp to maintain chronological order for LLM
    const sortedLogs = selectedLogs.sort((a, b) => {
      const timeA = new Date(a['@timestamp'] || a.timestamp || a._timestamp).getTime();
      const timeB = new Date(b['@timestamp'] || b.timestamp || b._timestamp).getTime();
      return timeA - timeB; // Ascending order (oldest first)
    });
    
    console.log(`getBalancedLogsForAnalysis returning ${sortedLogs.length} logs`);
    return sortedLogs;
  };

  // Helper function to get logs for LLM based on method
  const getLLMLogsForMethod = (logs: any[], anomalyContext: any, method: string) => {
    console.log(`getLLMLogsForMethod called with method: ${method}, total logs: ${logs.length}`);
    
    let selectedLogs;
    switch (method) {
      case 'method1-limited-first50':
        // Method 1: First 50 logs (original approach)
        selectedLogs = logs.slice(0, 50);
        break;
      
      case 'method2-limited-balanced':
        // Method 2: Balanced selection (50 logs)
        selectedLogs = getBalancedLogsForAnalysis(logs, anomalyContext);
        break;
      
      case 'method3-fetch-all':
        // Method 3: All logs (no limit)
        selectedLogs = logs;
        break;
      
      default:
        console.warn(`Unknown method: ${method}, using fallback`);
        selectedLogs = logs.slice(0, 50); // fallback
    }
    
    console.log(`getLLMLogsForMethod returning ${selectedLogs.length} logs for method: ${method}`);
    return selectedLogs;
  };

  // Function to analyze logs with LLM
  const analyzeLogs = async (logs: any[], anomalyContext: any, method: string = 'unknown') => {
    try {
      // Prepare the context for LLM
      const context = {
        anomalyTime: new Date(anomalyContext.startTime).toISOString(),
        entity: anomalyContext[ENTITY_VALUE_FIELD] || 'N/A',
        anomalyGrade: anomalyContext.anomalyGrade,
        confidence: anomalyContext.confidence,
        detectorName: props.detector?.name,
        logCount: logs.length,
        timeRange: {
          from: new Date(anomalyContext.startTime - 10 * 60 * 1000).toISOString(),
          to: new Date(anomalyContext.endTime + 10 * 60 * 1000).toISOString()
        }
      };

      const prompt = `You are analyzing logs around an anomaly detected by OpenSearch Anomaly Detection.

ANOMALY CONTEXT:
- Detection Time: ${context.anomalyTime}
- Entity: ${context.entity}
- Anomaly Grade: ${context.anomalyGrade}
- Confidence: ${context.confidence}
- Detector: ${context.detectorName}
- Log Count: ${context.logCount}
- Time Range: ${context.timeRange.from} to ${context.timeRange.to}

ANALYSIS METHOD: ${method}
LOG SELECTION SUMMARY:
- Total logs fetched: ${logs.length}
- Logs sent to LLM: ${getLLMLogsForMethod(logs, anomalyContext, method).length}
- Time range: ${context.timeRange.from} to ${context.timeRange.to}

LOGS TO ANALYZE:
${JSON.stringify(getLLMLogsForMethod(logs, anomalyContext, method), null, 2)}

Please analyze these logs and provide a concise incident summary in plain English, explaining:
1. What happened around the anomaly time
2. Potential root cause or contributing factors
3. Any patterns or correlations you notice
4. Recommended next steps for investigation

Keep the response under 300 words and focus on actionable insights.`;

      // Call the real OpenAI API via our server endpoint
      const response = await core.http.post('/api/anomaly_detectors/llm/analyze', {
        body: JSON.stringify({
          prompt: prompt,
          logs: logs,
          anomalyContext: context,
        }),
      });

      if (response.analysis) {
        return response.analysis;
      } else {
        throw new Error('No analysis returned from LLM API');
      }
    } catch (error: any) {
      console.error('Error analyzing logs with LLM:', error);
      
      // Provide more specific error messages
      if (error.message?.includes('OpenAI API key')) {
        throw new Error('OpenAI API not configured. Please set up your API key.');
      } else if (error.message?.includes('quota')) {
        throw new Error('OpenAI API quota exceeded. Please check your usage.');
      } else {
        throw new Error(`Failed to analyze logs: ${error.message || 'Unknown error'}`);
      }
    }
  };

  // Function to analyze logs with statistical analysis
  const analyzeLogsStatistically = async (logs: LogEntry[], anomalyContext: any) => {
    try {
      console.log(`Starting statistical analysis for anomaly at ${new Date(anomalyContext.startTime).toISOString()}`);
      console.log(`Analyzing ${logs.length} logs`);
      
      const result = await insightGenerator.generateInsights(logs, anomalyContext, props.detector);
      
      console.log(`Statistical analysis completed in ${result.metadata.analysisDuration}ms`);
      console.log(`Generated ${result.insights.length} insights`);
      
      return result.insights;
    } catch (error: any) {
      console.error('Error in statistical analysis:', error);
      throw new Error(`Failed to analyze logs statistically: ${error.message || 'Unknown error'}`);
    }
  };

  // Function to handle LLM analysis for an anomaly
  const handleLLMAnalysis = async (item: any) => {
    // build a unique identifier for the anomaly to make sure we don't analyze the same anomaly twice
    const anomalyKey = `${item.startTime}-${item.endTime}-${item[ENTITY_VALUE_FIELD] || 'no-entity'}`;
    
    // Check if already analyzed
    if (llmAnalysisResults[anomalyKey]) {
      return;
    }

    setLoadingLLMAnalysis(prev => ({ ...prev, [anomalyKey]: true }));
    setLlmAnalysisErrors(prev => ({ ...prev, [anomalyKey]: '' }));

    try {
      console.log(`\n=== LLM ANALYSIS START ===`);
      console.log(`Anomaly: ${new Date(item.startTime).toISOString()} to ${new Date(item.endTime).toISOString()}`);
      console.log(`Entity: ${item[ENTITY_VALUE_FIELD] || 'N/A'}`);
      
      const overallStartTime = Date.now();
      
      // CHOOSE YOUR METHOD HERE - Change this number to switch between methods:
      // 1 = Limited fetch (100) + First 50 logs
      // 2 = Limited fetch (100) + Balanced selection (50 logs)  
      // 3 = Fetch ALL logs + Send ALL to LLM
      const METHOD = 2; // <-- CHANGE THIS TO SWITCH METHODS
      
      let logs;
      let analysisMethod;
      
      if (METHOD === 1) {
        // Method 1: Original approach - limited fetch, first 50
        console.log(`[Method 1] Using limited fetch + first 50 logs`);
        logs = await fetchLogsForAnalysis(item.startTime, item.endTime, item);
        analysisMethod = 'method1-limited-first50';
      } else if (METHOD === 2) {
        // Method 2: Limited fetch, balanced selection
        console.log(`[Method 2] Using limited fetch + balanced selection`);
        logs = await fetchLogsForAnalysis(item.startTime, item.endTime, item);
        analysisMethod = 'method2-limited-balanced';
      } else if (METHOD === 3) {
        // Method 3: Fetch ALL logs, send ALL to LLM
        console.log(`[Method 3] Using fetch ALL + send ALL to LLM`);
        logs = await fetchAllLogsForAnalysis(item.startTime, item.endTime, item);
        analysisMethod = 'method3-fetch-all';
      } else {
        // Default fallback
        console.log(`[Default] Using limited fetch + balanced selection`);
        logs = await fetchLogsForAnalysis(item.startTime, item.endTime, item);
        analysisMethod = 'method2-limited-balanced';
      }
      
      const llmStartTime = Date.now();
      const analysis = await analyzeLogs(logs, item, analysisMethod);
      const llmEndTime = Date.now();
      
      const overallEndTime = Date.now();
      
      console.log(`\n=== PERFORMANCE METRICS ===`);
      console.log(`Method: ${METHOD}`);
      console.log(`Total logs fetched: ${logs.length}`);
      console.log(`Overall duration: ${overallEndTime - overallStartTime}ms`);
      console.log(`LLM analysis duration: ${llmEndTime - llmStartTime}ms`);
      console.log(`Estimated token count: ${Math.ceil(JSON.stringify(logs).length / 4)}`);
      console.log(`=== LLM ANALYSIS END ===\n`);
      
      setLlmAnalysisResults(prev => ({ ...prev, [anomalyKey]: analysis }));
    } catch (error: any) {
      console.error(`LLM Analysis failed:`, error);
      setLlmAnalysisErrors(prev => ({ 
        ...prev, 
        [anomalyKey]: error.message || 'Failed to analyze logs' 
      }));
    } finally {
      setLoadingLLMAnalysis(prev => ({ ...prev, [anomalyKey]: false }));
    }
  };

  // Function to handle statistical analysis for an anomaly
  const handleStatisticalAnalysis = async (item: any) => {
    // build a unique identifier for the anomaly to make sure we don't analyze the same anomaly twice
    const anomalyKey = `${item.startTime}-${item.endTime}-${item[ENTITY_VALUE_FIELD] || 'no-entity'}`;
    
    // Check if already analyzed
    if (statisticalAnalysisResults[anomalyKey]) {
      return;
    }

    setLoadingStatisticalAnalysis(prev => ({ ...prev, [anomalyKey]: true }));
    setStatisticalAnalysisErrors(prev => ({ ...prev, [anomalyKey]: '' }));

    try {
      console.log(`\n=== STATISTICAL ANALYSIS START ===`);
      console.log(`Anomaly: ${new Date(item.startTime).toISOString()} to ${new Date(item.endTime).toISOString()}`);
      console.log(`Entity: ${item[ENTITY_VALUE_FIELD] || 'N/A'}`);
      
      const overallStartTime = Date.now();
      
      // Fetch logs for analysis (using less restrictive approach for better statistical analysis)
      const logs = await fetchLogsForStatisticalAnalysis(item.startTime, item.endTime, item);
      console.log(`Fetched ${logs.length} logs for statistical analysis (10 min before + 5 min after anomaly)`);
      
      // Convert to LogEntry format
      const logEntries: LogEntry[] = logs.map((log: any) => ({
        timestamp: new Date(log['@timestamp'] || log.timestamp || log._timestamp).getTime(),
        level: log.level || log.severity,
        message: log.message || log.msg || JSON.stringify(log),
        ...log
      }));
      
      const analysisStartTime = Date.now();
      const insights = await analyzeLogsStatistically(logEntries, item);
      const analysisEndTime = Date.now();
      
      const overallEndTime = Date.now();
      
      console.log(`\n=== PERFORMANCE METRICS ===`);
      console.log(`Total logs fetched: ${logs.length}`);
      console.log(`Overall duration: ${overallEndTime - overallStartTime}ms`);
      console.log(`Statistical analysis duration: ${analysisEndTime - analysisStartTime}ms`);
      console.log(`Generated insights: ${insights.length}`);
      console.log(`=== STATISTICAL ANALYSIS END ===\n`);
      
      setStatisticalAnalysisResults(prev => ({ ...prev, [anomalyKey]: insights }));
    } catch (error: any) {
      console.error(`Statistical Analysis failed:`, error);
      setStatisticalAnalysisErrors(prev => ({ 
        ...prev, 
        [anomalyKey]: error.message || 'Failed to analyze logs statistically' 
      }));
    } finally {
      setLoadingStatisticalAnalysis(prev => ({ ...prev, [anomalyKey]: false }));
    }
  };

  const handleOpenDiscover = async (startTime: number, endTime: number, item: any) => {
    try {
      // calculate time range with 10-minute buffer on each side per customer request
      const TEN_MINUTES_IN_MS = 10 * 60 * 1000;
      const startISO = new Date(startTime - TEN_MINUTES_IN_MS).toISOString();
      const endISO = new Date(endTime + TEN_MINUTES_IN_MS).toISOString();

      const basePath = `${window.location.origin}${window.location.pathname.split('/app/')[0]}`;
      const savedObjectsClient = getSavedObjectsClient();
      const indexPatternTitle = props.detectorIndices.join(',');
      
      let discoverUrl = '';
      let indexPatternId = '';

      if (getDataSourceEnabled().enabled) {
        const currentWorkspace = await core.workspaces.currentWorkspace$.pipe(first()).toPromise();
        const currentWorkspaceId = currentWorkspace?.id;

        // try to find an existing index pattern with this title
        let findExistingIndexPatternOptions: any = {
          type: 'index-pattern',
          fields: ['title'],
          perPage: 10000,
        };

        if (currentWorkspaceId) {
          findExistingIndexPatternOptions.workspaces = [currentWorkspaceId];
        }

        const indexPatternResponse = await savedObjectsClient.find(findExistingIndexPatternOptions);
        
        // Filter by title and data source id
        const matchingIndexPatterns = indexPatternResponse.savedObjects.filter(
          (obj: any) => {
            const titleMatches = obj.attributes.title === indexPatternTitle;
            
            const dataSourceRef = obj.references?.find(
              (ref: any) => ref.type === 'data-source' && ref.name === 'dataSource'
            );
            const dataSourceMatches = dataSourceRef?.id === dataSourceId;
            
            return titleMatches && dataSourceMatches;
          }
        );
        
        if (matchingIndexPatterns.length > 0) {
          indexPatternId = matchingIndexPatterns[0].id;
        } else {
          // try to create a new index pattern
          try {
            const createPayload: any = {
              attributes: {
                title: indexPatternTitle,
                timeFieldName: props.detectorTimeField,
              },
            };

            createPayload.references = [
              {
                id: dataSourceId,
                type: 'data-source',
                name: 'dataSource'
              }
            ];

            if (currentWorkspaceId) {
              createPayload.workspaces = [currentWorkspaceId];
            }

            const newIndexPattern = await savedObjectsClient.create('index-pattern', createPayload.attributes, {
              references: createPayload.references,
              workspaces: createPayload.workspaces,
            });
            indexPatternId = newIndexPattern.id;

            getNotifications().toasts.addSuccess(`Created new index pattern: ${indexPatternTitle}`);
          } catch (error: any) {
            getNotifications().toasts.addDanger(`Failed to create index pattern: ${error.message}`);
            return;
          }
        }

        if (dataSourceId) {
          try {
            const dataSourceObject = await savedObjectsClient.get('data-source', dataSourceId);
            const attributes = dataSourceObject.attributes as any;
            const dataSourceTitle = attributes?.title;
            const dataSourceEngineType = attributes?.dataSourceEngineType;

            // Build filters for HC detector
            let filters: any[] = [];
            if (props.isHCDetector && item[ENTITY_VALUE_FIELD]) {
              const entityValues = item[ENTITY_VALUE_FIELD].split('\n').map((s: string) => s.trim()).filter(Boolean);
              filters = entityValues.map((entityValue: string) => {
                const [field, value] = entityValue.split(': ').map((s: string) => s.trim());
                const mockField = { name: field, type: 'string' };
                const mockIndexPattern = { 
                  id: indexPatternId, 
                  title: indexPatternTitle,
                  fields: [],
                  getFieldByName: () => undefined,
                  getComputedFields: () => [],
                  getScriptedFields: () => [],
                  getSourceFilter: () => undefined,
                  getTimeField: () => undefined,
                  isTimeBased: () => false
                } as unknown as IIndexPattern;
                return opensearchFilters.buildPhraseFilter(mockField, value, mockIndexPattern);
              });
            }

            // Get feature output values for this anomaly and add them as filters
            const featureValues = getFeatureOutputValues(item.plotTime || item.endTime, item.entity);
            Object.keys(featureValues).forEach((featureName: string) => {
              const featureValue = featureValues[featureName];
              const mockField = { name: featureName, type: 'number' };
              const mockIndexPattern = { 
                id: indexPatternId, 
                title: indexPatternTitle,
                fields: [],
                getFieldByName: () => undefined,
                getComputedFields: () => [],
                getScriptedFields: () => [],
                getSourceFilter: () => undefined,
                getTimeField: () => undefined,
                isTimeBased: () => false
              } as unknown as IIndexPattern;
              filters.push(opensearchFilters.buildPhraseFilter(mockField, featureValue, mockIndexPattern));
            });

            // Build app state with filters
            const appState = {
              discover: {
                columns: ['_source'],
                isDirty: false,
                sort: []
              },
              metadata: {
                view: 'discover'
              },
              filters: filters
            };

            // Build global state with time range
            const globalState = {
              filters: [],
              refreshInterval: {
                pause: true,
                value: 0
              },
              time: {
                from: startISO,
                to: endISO
              }
            };

            // Build query state
            const queryState = {
              filters: filters,
              query: {
                dataset: {
                  dataSource: {
                    id: dataSourceId,
                    title: dataSourceTitle,
                    type: dataSourceEngineType
                  },
                  id: indexPatternId,
                  isRemoteDataset: false,
                  timeFieldName: props.detectorTimeField,
                  title: indexPatternTitle,
                  type: 'INDEX_PATTERN'
                },
                language: 'kuery',
                query: ''
              }
            };

            // Generate URL using setStateToOsdUrl
            let url = `${basePath}/app/data-explorer/discover#/`;
            url = setStateToOsdUrl('_a', appState, { useHash: false }, url);
            url = setStateToOsdUrl('_g', globalState, { useHash: false }, url);
            url = setStateToOsdUrl('_q', queryState, { useHash: false }, url);
            
            discoverUrl = url;
            
            window.open(discoverUrl, '_blank');
            
          } catch (error: any) {
            console.error("Error fetching data source details:", error);
          }
        }

      } else {
        // try to find an existing index pattern with this title
        const indexPatternResponse = await savedObjectsClient.find({
          type: 'index-pattern',
          fields: ['title'],
          search: `"${indexPatternTitle}"`,
          searchFields: ['title'],
        });
        
        if (indexPatternResponse.savedObjects.length > 0) {
          indexPatternId = indexPatternResponse.savedObjects[0].id;
        } else {
          // try to create a new index pattern
          try {
            const newIndexPattern = await savedObjectsClient.create('index-pattern', {
              title: indexPatternTitle,
              timeFieldName: props.detectorTimeField,
            });
            
            indexPatternId = newIndexPattern.id;

            getNotifications().toasts.addSuccess(`Created new index pattern: ${indexPatternTitle}`);
          } catch (error: any) {
            getNotifications().toasts.addDanger(`Failed to create index pattern: ${error.message}`);
            return;
          }
        }
        
        // Build filters for HC detector
        let filters: any[] = [];
        if (props.isHCDetector && item[ENTITY_VALUE_FIELD]) {
          const entityValues = item[ENTITY_VALUE_FIELD].split('\n').map((s: string) => s.trim()).filter(Boolean);
          filters = entityValues.map((entityValue: string) => {
            const [field, value] = entityValue.split(': ').map((s: string) => s.trim());
            const mockField = { name: field, type: 'string' };
            const mockIndexPattern = { 
              id: indexPatternId, 
              title: indexPatternTitle,
              fields: [],
              getFieldByName: () => undefined,
              getComputedFields: () => [],
              getScriptedFields: () => [],
              getSourceFilter: () => undefined,
              getTimeField: () => undefined,
              isTimeBased: () => false
            } as unknown as IIndexPattern;
            return opensearchFilters.buildPhraseFilter(mockField, value, mockIndexPattern);
          });
        }

        // Get feature output values for this anomaly and add them as filters
        const featureValues = getFeatureOutputValues(item.plotTime || item.endTime, item.entity);
        Object.keys(featureValues).forEach((featureName: string) => {
          const featureValue = featureValues[featureName];
          const mockField = { name: featureName, type: 'number' };
          const mockIndexPattern = { 
            id: indexPatternId, 
            title: indexPatternTitle,
            fields: [],
            getFieldByName: () => undefined,
            getComputedFields: () => [],
            getScriptedFields: () => [],
            getSourceFilter: () => undefined,
            getTimeField: () => undefined,
            isTimeBased: () => false
          } as unknown as IIndexPattern;
          filters.push(opensearchFilters.buildPhraseFilter(mockField, featureValue, mockIndexPattern));
        });

        // Build app state with filters
        const appState = {
          discover: {
            columns: ['_source'],
            isDirty: false,
            sort: []
          },
          metadata: {
            indexPattern: indexPatternId,
            view: 'discover'
          },
          filters: filters
        };

        // Build global state with time range
        const globalState = {
          filters: [],
          refreshInterval: {
            pause: true,
            value: 0
          },
          time: {
            from: startISO,
            to: endISO
          }
        };

        // Build query state
        const queryState = {
          filters: filters,
          query: {
            language: 'kuery',
            query: ''
          }
        };

        // Generate URL using setStateToOsdUrl
        let url = `${basePath}/app/data-explorer/discover#/`;
        url = setStateToOsdUrl('_a', appState, { useHash: false }, url);
        url = setStateToOsdUrl('_g', globalState, { useHash: false }, url);
        url = setStateToOsdUrl('_q', queryState, { useHash: false }, url);
        
        discoverUrl = url;
        
        window.open(discoverUrl, '_blank');
      }
    } catch (error: any) {
      getNotifications().toasts.addDanger('Error opening discover view');
    }
  };

  const getCustomColumns = () => {
    const columns = [...staticColumn] as any[];
    
    // Add AI Insights column
    const aiInsightsColumn = {
      field: 'aiInsights',
      name: (
        <EuiText size="xs" style={{ fontWeight: 'bold' }}>
          <b>AI Insights</b>{' '}
          <EuiToolTip content="AI-powered analysis of logs around the anomaly time">
            <EuiIcon type="iInCircle" />
          </EuiToolTip>
        </EuiText>
      ),
      align: 'center',
      truncateText: false,
      width: '180px',
      render: (value: any, item: any) => {
        const anomalyKey = `${item.startTime}-${item.endTime}-${item[ENTITY_VALUE_FIELD] || 'no-entity'}`;
        const isLoading = loadingLLMAnalysis[anomalyKey];
        const analysis = llmAnalysisResults[anomalyKey];
        const error = llmAnalysisErrors[anomalyKey];
        const isPopoverOpen = openLLMPopovers[anomalyKey];

        if (isLoading) {
          return (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
              <EuiLoadingSpinner size="s" />
              <EuiText size="xs">Analyzing...</EuiText>
            </div>
          );
        }

        if (error) {
          return (
            <EuiToolTip content={error}>
              <EuiButton
                size="s"
                color="danger"
                onClick={() => handleLLMAnalysis(item)}
                iconType="refresh"
              >
                Retry
              </EuiButton>
            </EuiToolTip>
          );
        }

        if (analysis) {
          return (
            <EuiPopover
              button={
                <EuiButton
                  size="s"
                  color="primary"
                  iconType="inspect"
                  onClick={() => setOpenLLMPopovers(prev => ({ ...prev, [anomalyKey]: !isPopoverOpen }))}
                >
                  View Analysis
                </EuiButton>
              }
              isOpen={isPopoverOpen}
              closePopover={() => setOpenLLMPopovers(prev => ({ ...prev, [anomalyKey]: false }))}
              anchorPosition="rightCenter"
              panelPaddingSize="m"
              style={{ maxWidth: '400px' }}
            >
              <EuiPopoverTitle>AI Analysis</EuiPopoverTitle>
              <div style={{ maxWidth: '350px', maxHeight: '300px', overflow: 'auto' }}>
                <EuiText size="s" style={{ whiteSpace: 'pre-line' }}>
                  {analysis}
                </EuiText>
              </div>
              <EuiPopoverFooter>
                <EuiButtonEmpty
                  size="xs"
                  onClick={() => navigator.clipboard.writeText(analysis)}
                  iconType="copy"
                >
                  Copy to clipboard
                </EuiButtonEmpty>
              </EuiPopoverFooter>
            </EuiPopover>
          );
        }

        return (
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <EuiButton
              size="s"
              color="primary"
              onClick={() => handleLLMAnalysis(item)}
              iconType="brain"
            >
              Analyze
            </EuiButton>
          </div>
        );
      }
    };

    // Add Statistical Insights column
    const statisticalInsightsColumn = {
      field: 'statisticalInsights',
      name: (
        <EuiText size="xs" style={{ fontWeight: 'bold' }}>
          <b>Statistical Insights</b>{' '}
          <EuiToolTip content="Statistical analysis of logs around the anomaly time">
            <EuiIcon type="iInCircle" />
          </EuiToolTip>
        </EuiText>
      ),
      align: 'center',
      truncateText: false,
      width: '200px',
      render: (value: any, item: any) => {
        const anomalyKey = `${item.startTime}-${item.endTime}-${item[ENTITY_VALUE_FIELD] || 'no-entity'}`;
        const isLoading = loadingStatisticalAnalysis[anomalyKey];
        const insights = statisticalAnalysisResults[anomalyKey];
        const error = statisticalAnalysisErrors[anomalyKey];
        const isPopoverOpen = openStatisticalPopovers[anomalyKey];

        if (isLoading) {
          return (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
              <EuiLoadingSpinner size="s" />
              <EuiText size="xs">Analyzing...</EuiText>
            </div>
          );
        }

        if (error) {
          return (
            <EuiToolTip content={error}>
              <EuiButton
                size="s"
                color="danger"
                onClick={() => handleStatisticalAnalysis(item)}
                iconType="refresh"
              >
                Retry
              </EuiButton>
            </EuiToolTip>
          );
        }

        if (insights && insights.length > 0) {
          const criticalInsights = insights.filter(i => i.severity === 'critical').length;
          const highInsights = insights.filter(i => i.severity === 'high').length;
          const actionableInsights = insights.filter(i => i.actionable).length;
          
          const buttonColor = criticalInsights > 0 ? 'danger' : highInsights > 0 ? 'warning' : 'primary';
          const buttonText = criticalInsights > 0 ? `${criticalInsights} Critical` : 
                           highInsights > 0 ? `${highInsights} High` : 
                           `${insights.length} Insights`;

          return (
            <EuiPopover
              button={
                <EuiButton
                  size="s"
                  color={buttonColor}
                  iconType="stats"
                  onClick={() => setOpenStatisticalPopovers(prev => ({ ...prev, [anomalyKey]: !isPopoverOpen }))}
                >
                  {buttonText}
                </EuiButton>
              }
              isOpen={isPopoverOpen}
              closePopover={() => setOpenStatisticalPopovers(prev => ({ ...prev, [anomalyKey]: false }))}
              anchorPosition="rightCenter"
              panelPaddingSize="m"
              style={{ maxWidth: '500px' }}
            >
              <EuiPopoverTitle>
                Statistical Analysis Summary
                <EuiText size="xs" color="subdued">
                  {insights.length} insights • {actionableInsights} actionable
                </EuiText>
              </EuiPopoverTitle>
              <div style={{ maxWidth: '450px', maxHeight: '400px', overflow: 'auto' }}>
                <EuiText size="s" style={{ 
                  whiteSpace: 'pre-line', 
                  lineHeight: '1.5',
                  fontFamily: 'monospace',
                  backgroundColor: '#f8f9fa',
                  padding: '12px',
                  borderRadius: '4px',
                  border: '1px solid #e0e0e0'
                }}>
                  {formatInsightsForDisplay(insights)}
                </EuiText>
              </div>
              <EuiPopoverFooter>
                <EuiButtonEmpty
                  size="xs"
                  onClick={() => navigator.clipboard.writeText(formatInsightsForDisplay(insights))}
                  iconType="copy"
                >
                  Copy summary
                </EuiButtonEmpty>
              </EuiPopoverFooter>
            </EuiPopover>
          );
        }

        return (
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <EuiButton
              size="s"
              color="primary"
              onClick={() => handleStatisticalAnalysis(item)}
              iconType="stats"
            >
              Analyze
            </EuiButton>
          </div>
        );
      }
    };

    // Insert both columns before Actions column
    const actionsColumnIndex = columns.findIndex((column: any) => column.field === 'actions');
    if (actionsColumnIndex !== -1) {
      // Insert AI Insights first, then Statistical Insights
      columns.splice(actionsColumnIndex, 0, aiInsightsColumn);
      columns.splice(actionsColumnIndex + 1, 0, statisticalInsightsColumn);
      
      // Update actions column
      const actionsColumn = { ...columns[actionsColumnIndex + 2] } as any;
      
      if (actionsColumn.actions && Array.isArray(actionsColumn.actions)) {
        actionsColumn.actions = [
          {
            ...actionsColumn.actions[0],
            onClick: (item: any) => handleOpenDiscover(item.startTime, item.endTime, item),
          },
        ];
      }
      
      columns[actionsColumnIndex + 2] = actionsColumn;
    } else {
      // If no actions column, just add both columns at the end
      columns.push(aiInsightsColumn);
      columns.push(statisticalInsightsColumn);
    }
    
    return columns;
  };

  const sortFieldCompare = (field: string, sortDirection: SORT_DIRECTION) => {
    return (a: any, b: any) => {
      if (get(a, `${field}`) > get(b, `${field}`))
        return sortDirection === SORT_DIRECTION.ASC ? 1 : -1;
      if (get(a, `${field}`) < get(b, `${field}`))
        return sortDirection === SORT_DIRECTION.ASC ? -1 : 1;
      return 0;
    };
  };

  useEffect(() => {
    // Only return anomalies if they exist. If high-cardinality: only show when a heatmap cell is selected
    let anomalies =
      props.anomalies &&
      ((props.isHCDetector && props.selectedHeatmapCell) || !props.isHCDetector)
        ? props.anomalies.filter((anomaly) => anomaly.anomalyGrade > 0)
        : [];

    if (props.isHCDetector) {
      anomalies = anomalies.map((anomaly) => {
        return {
          ...anomaly,
          [ENTITY_VALUE_FIELD]: convertToCategoryFieldAndEntityString(
            get(anomaly, 'entity', [])
          ),
        };
      });
    }

    anomalies.sort(
      sortFieldCompare(
        state.queryParams.sortField,
        state.queryParams.sortDirection
      )
    );

    setTargetAnomalies(
      anomalies.slice(
        state.page * state.queryParams.size,
        (state.page + 1) * state.queryParams.size
      )
    );
  }, [props.anomalies, state]);

  const isLoading = false;

  const handleTableChange = ({ page: tablePage = {}, sort = {} }: any) => {
    const { index: page, size } = tablePage;
    const { field: sortField, direction: sortDirection } = sort;
    setState({
      page,
      queryParams: {
        ...state.queryParams,
        size,
        sortField,
        sortDirection,
      },
    });
  };

  const sorting = {
    sort: {
      direction: state.queryParams.sortDirection,
      field: state.queryParams.sortField,
    },
  };
  const pagination = {
    pageIndex: state.page,
    pageSize: state.queryParams.size,
    totalItemCount: Math.min(MAX_ANOMALIES, totalAnomalies.length),
    pageSizeOptions: [10, 30, 50, 100],
  };
  
  const customColumns = getCustomColumns();

  return (
    <ContentPanel
      title={getTitleWithCount('Anomaly occurrences', totalAnomalies.length)}
      titleDataTestSubj="anomalyOccurrencesHeader"
      titleSize="xs"
      titleClassName="preview-title"
    >
      <EuiBasicTable
        items={targetAnomalies}
        columns={
          props.isHCDetector && props.isHistorical
            ? [
                ...customColumns.slice(0, 2),
                entityValueColumn,
                ...customColumns.slice(3),
              ]
            : props.isHCDetector
            ? [
                ...customColumns.slice(0, 2),
                entityValueColumn,
                ...customColumns.slice(2),
              ]
            : props.isHistorical
            ? [...customColumns.slice(0, 2), ...customColumns.slice(3)]
            : customColumns
        }
        onChange={handleTableChange}
        sorting={sorting}
        pagination={pagination}
        noItemsMessage={
          isLoading ? (
            'Loading anomaly results...'
          ) : (
            <EuiEmptyPrompt
              style={{ maxWidth: '45em' }}
              body={
                <EuiText data-test-subj="noAnomaliesMessage" size="s">
                  <p>There are no anomalies currently.</p>
                </EuiText>
              }
            />
          )
        }
      />
    </ContentPanel>
  );
}
